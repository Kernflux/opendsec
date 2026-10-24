package netpol

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// The per-sandbox data plane goes over netlink (spec §20.2): the nft and ip
// tools re-read the whole ruleset, or copy the mount table, on each call,
// which at thousands of sandboxes per node cost ~300 ms (nft) and ~100 ms
// (ip -n) per operation. Only the edge's base rules, set once, use nft.

// nl is the edge's nftables connection: its operations are batched and
// serialized.
type nl struct {
	mu      sync.Mutex
	conn    *nftables.Conn
	table   *nftables.Table
	private *nftables.Set
	sb      *nftables.Set
	// limited: slot -> how many port-limited set pairs it may have
	// (indices 0..n-1), read from the table once (indexed), then kept up
	// to date. Listing the table's sets on every change instead costs
	// O(sandboxes) under mu and made creations slow down as an edge filled.
	limited map[int]int
	indexed bool
}

func newNL(table string) (*nl, error) {
	c, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, err
	}
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: table}
	return &nl{conn: c, table: t,
		private: &nftables.Set{Table: t, Name: "private", KeyType: nftables.TypeIPAddr, Interval: true},
		sb:      &nftables.Set{Table: t, Name: "sb", IsMap: true, DataType: nftables.TypeVerdict}}, nil
}

func (n *nl) close() { n.conn.CloseLasting() }

func ip4(ip net.IP) []byte { return []byte(ip.To4()) }

func ifname(name string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, name)
	return b
}

func (n *nl) slotSets(slot int) (learned, nets *nftables.Set) {
	return &nftables.Set{Table: n.table, Name: fmt.Sprintf("a%d", slot), KeyType: nftables.TypeIPAddr, HasTimeout: true},
		&nftables.Set{Table: n.table, Name: fmt.Sprintf("n%d", slot), KeyType: nftables.TypeIPAddr, Interval: true}
}

// limitedSets are the sets of slot's k-th port-limited targets.
func (n *nl) limitedSets(slot, k int) (learned, nets *nftables.Set) {
	return &nftables.Set{Table: n.table, Name: fmt.Sprintf("a%dp%d", slot, k), KeyType: nftables.TypeIPAddr, HasTimeout: true},
		&nftables.Set{Table: n.table, Name: fmt.Sprintf("n%dp%d", slot, k), KeyType: nftables.TypeIPAddr, Interval: true}
}

// isLimitedSet reports whether name is one of slot's port-limited sets,
// with its index.
func isLimitedSet(name string, slot int) (int, bool) {
	s, k, ok := parseLimitedSet(name)
	return k, ok && s == slot
}

// parseLimitedSet parses a port-limited set's name (a<slot>p<k> or
// n<slot>p<k>).
func parseLimitedSet(name string) (slot, k int, ok bool) {
	if len(name) < 4 || (name[0] != 'a' && name[0] != 'n') {
		return 0, 0, false
	}
	a, b, found := strings.Cut(name[1:], "p")
	if !found {
		return 0, 0, false
	}
	slot, err1 := strconv.Atoi(a)
	k, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil || slot < 0 || k < 0 || strconv.Itoa(slot) != a || strconv.Itoa(k) != b {
		return 0, 0, false
	}
	return slot, k, true
}

func (n *nl) slotChain(slot int) *nftables.Chain {
	return &nftables.Chain{Table: n.table, Name: fmt.Sprintf("s%d", slot)}
}

func (n *nl) mapKey(veth string, ip net.IP) []byte { return append(ifname(veth), ip4(ip)...) }

// daddrIn loads the IPv4 destination and matches it against set (only
// IPv4 reaches the sandbox chains: the base chain drops IPv6 first).
func daddrIn(set string, id uint32) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Lookup{SourceRegister: 1, SetName: set, SetID: id},
	}
}

// portMatch matches the packet's protocol and destination port against
// spec (spec §29.2).
func portMatch(proto byte, s portSpec) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: binary.BigEndian.AppendUint16(nil, s.lo),
			ToData: binary.BigEndian.AppendUint16(nil, s.hi)},
	}
}

// learnedSet is one set of learned addresses: the any-port one (k < 0) or
// the k-th port-limited one.
type learnedSet struct {
	k   int
	ips map[string]time.Time
}

// setSlot (re)writes slot's sets and chain for p, re-adding the learned
// addresses in keep (by set), and with mapEntry its entry in the dispatch
// map; one transaction. Port-limited sets p no longer has go afterwards.
func (n *nl) setSlot(a *Attachment, p *policy, keep []learnedSet, mapEntry bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := n.conn
	learned, nets := n.slotSets(a.Slot)
	type sets struct{ learned, nets *nftables.Set }
	all := []sets{{learned, nets}}
	for k := range p.limited {
		l, ns := n.limitedSets(a.Slot, k)
		all = append(all, sets{l, ns})
	}
	for i, s := range all {
		if err := c.AddSet(s.learned, nil); err != nil {
			return err
		}
		if err := c.AddSet(s.nets, nil); err != nil {
			return err
		}
		c.FlushSet(s.learned)
		c.FlushSet(s.nets)
		t := &p.targets
		if i > 0 {
			t = &p.limited[i-1].targets
		}
		if els := intervalElements(t.nets); len(els) > 0 {
			if err := c.SetAddElements(s.nets, els); err != nil {
				return err
			}
		}
	}
	for _, ls := range keep {
		if ls.k >= len(p.limited) {
			continue
		}
		if els := timedElements(ls.ips); len(els) > 0 {
			if err := c.SetAddElements(all[ls.k+1].learned, els); err != nil {
				return err
			}
		}
	}
	ch := c.AddChain(n.slotChain(a.Slot))
	c.FlushChain(ch)
	accept, drop := &expr.Verdict{Kind: expr.VerdictAccept}, &expr.Verdict{Kind: expr.VerdictDrop}
	refresh := func(s *nftables.Set) expr.Any {
		return &expr.Dynset{SrcRegKey: 1, SetName: s.Name, SetID: s.ID, Operation: unix.NFT_DYNSET_OP_UPDATE, Timeout: learnIdle}
	}
	// Allowed networks (private ones included) come before the private
	// drop; learned addresses and "*" after it. A port-limited rule loads
	// the address first (the lookup), then matches protocol and port, then
	// refreshes the learned address from register 1 again.
	rules := [][]expr.Any{append(daddrIn(nets.Name, nets.ID), accept)}
	for i, l := range p.limited {
		for _, proto := range l.ports.protos() {
			r := append(daddrIn(all[i+1].nets.Name, all[i+1].nets.ID), portMatch(proto, l.ports)...)
			rules = append(rules, append(r, accept))
		}
	}
	rules = append(rules, append(daddrIn("private", 0), drop),
		append(daddrIn(learned.Name, learned.ID), refresh(learned), accept))
	for i, l := range p.limited {
		s := all[i+1].learned
		for _, proto := range l.ports.protos() {
			r := append(portMatch(proto, l.ports), daddrIn(s.Name, s.ID)...)
			rules = append(rules, append(r, refresh(s), accept))
		}
		if l.all {
			for _, proto := range l.ports.protos() {
				rules = append(rules, append(portMatch(proto, l.ports), accept))
			}
		}
	}
	if p.all {
		rules = append(rules, []expr.Any{accept})
	}
	rules = append(rules, []expr.Any{drop})
	for _, r := range rules {
		c.AddRule(&nftables.Rule{Table: n.table, Chain: ch, Exprs: r})
	}
	if mapEntry {
		if err := c.SetAddElements(n.sb, []nftables.SetElement{{Key: n.mapKey(a.Veth, a.SandboxIP),
			VerdictData: &expr.Verdict{Kind: expr.VerdictJump, Chain: ch.Name}}}); err != nil {
			return err
		}
	}
	if err := c.Flush(); err != nil {
		return err
	}
	n.dropLimitedSets(a.Slot, len(p.limited))
	if n.indexed && len(p.limited) > n.limited[a.Slot] {
		n.limited[a.Slot] = len(p.limited)
	}
	return nil
}

// dropLimitedSets deletes slot's port-limited sets from index from on (the
// chain no longer refers to them). A missing set fails a whole transaction,
// so each goes on its own. Called with mu held.
func (n *nl) dropLimitedSets(slot, from int) {
	if !n.indexLimited() {
		return
	}
	for k := from; k < n.limited[slot]; k++ {
		l, ns := n.limitedSets(slot, k)
		for _, s := range []*nftables.Set{l, ns} {
			n.conn.DelSet(s)
			n.conn.Flush()
		}
	}
	if from > 0 {
		n.limited[slot] = from
	} else {
		delete(n.limited, slot)
	}
}

// indexLimited reads which port-limited sets the table has, once (sets a
// previous edge process left are found this way). Called with mu held.
func (n *nl) indexLimited() bool {
	if n.indexed {
		return true
	}
	sets, err := n.conn.GetSets(n.table)
	if err != nil {
		return false
	}
	n.limited = map[int]int{}
	for _, s := range sets {
		if slot, k, ok := parseLimitedSet(s.Name); ok && k >= n.limited[slot] {
			n.limited[slot] = k + 1
		}
	}
	n.indexed = true
	return true
}

// learn adds addresses (ip -> expiry) to slot's learned sets.
func (n *nl) learn(slot int, add []learnedSet) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, ls := range add {
		s, _ := n.slotSets(slot)
		if ls.k >= 0 {
			s, _ = n.limitedSets(slot, ls.k)
		}
		if err := n.conn.SetAddElements(s, timedElements(ls.ips)); err != nil {
			return err
		}
	}
	return n.conn.Flush()
}

// removeSlot deletes slot's map entry (veth != ""), chain and sets. A
// missing object fails a whole transaction, so each goes on its own.
func (n *nl) removeSlot(slot int, veth string, ip net.IP) {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := n.conn
	if veth != "" && ip != nil {
		if c.SetDeleteElements(n.sb, []nftables.SetElement{{Key: n.mapKey(veth, ip)}}) == nil {
			c.Flush()
		}
	}
	learned, nets := n.slotSets(slot)
	c.DelChain(n.slotChain(slot))
	c.Flush()
	for _, s := range []*nftables.Set{learned, nets} {
		c.DelSet(s)
		c.Flush()
	}
	n.dropLimitedSets(slot, 0)
}

// slots lists the slot chains in the table.
func (n *nl) slots() (map[int]bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	chains, err := n.conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return nil, err
	}
	out := map[int]bool{}
	for _, ch := range chains {
		var s int
		if ch.Table.Name == n.table.Name && strings.HasPrefix(ch.Name, "s") {
			if _, err := fmt.Sscanf(ch.Name, "s%d", &s); err == nil && ch.Name == fmt.Sprintf("s%d", s) {
				out[s] = true
			}
		}
	}
	return out, nil
}

func timedElements(ips map[string]time.Time) []nftables.SetElement {
	var out []nftables.SetElement
	now := time.Now()
	for ip, exp := range ips {
		if d := exp.Sub(now); d > time.Second {
			if b := net.ParseIP(ip).To4(); b != nil {
				out = append(out, nftables.SetElement{Key: b, Timeout: d.Truncate(time.Second)})
			}
		}
	}
	return out
}

// intervalElements turns networks into interval set elements, merged: the
// kernel takes no overlapping intervals (nft merges them in userspace).
func intervalElements(nets []*net.IPNet) []nftables.SetElement {
	type rng struct{ lo, hi uint64 } // [lo, hi)
	var rs []rng
	for _, n := range nets {
		ones, _ := n.Mask.Size()
		lo := uint64(binary.BigEndian.Uint32(n.IP.To4()))
		rs = append(rs, rng{lo, lo + 1<<(32-ones)})
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo < rs[j].lo })
	var merged []rng
	for _, r := range rs {
		if k := len(merged) - 1; k >= 0 && r.lo <= merged[k].hi {
			merged[k].hi = max(merged[k].hi, r.hi)
			continue
		}
		merged = append(merged, r)
	}
	var out []nftables.SetElement
	for _, r := range merged {
		out = append(out, nftables.SetElement{Key: u32IP(uint32(r.lo))})
		if r.hi < 1<<32 { // else the interval runs to the end of the space
			out = append(out, nftables.SetElement{Key: u32IP(uint32(r.hi)), IntervalEnd: true})
		}
	}
	return out
}

// ---- namespaces and links ---------------------------------------------------------

// inNetns runs fn on a thread moved into the namespace at path.
func inNetns(path string, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with the goroutine
		ns, err := netns.GetFromPath(path)
		if err != nil {
			errc <- err
			return
		}
		defer ns.Close()
		if err := netns.Set(ns); err != nil {
			errc <- err
			return
		}
		errc <- fn()
	}()
	return <-errc
}

// newNetns creates the named namespace (/run/netns/<name>), or with pid > 0
// names that process's.
func newNetns(name string, pid int) error {
	if err := os.MkdirAll(netnsDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(netnsDir, name)
	if pid <= 0 {
		errc := make(chan error, 1)
		go func() {
			runtime.LockOSThread() // never unlocked: it ends in the new namespace
			ns, err := netns.NewNamed(name)
			if err == nil {
				ns.Close()
			}
			errc <- err
		}()
		return <-errc
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDONLY, 0o444)
	if err != nil {
		return err
	}
	f.Close()
	if err := unix.Mount(fmt.Sprintf("/proc/%d/ns/net", pid), path, "", unix.MS_BIND, ""); err != nil {
		os.Remove(path)
		return fmt.Errorf("bind netns of %d: %w", pid, err)
	}
	return nil
}

func deleteNetns(name string) {
	path := filepath.Join(netnsDir, name)
	unix.Unmount(path, unix.MNT_DETACH)
	os.Remove(path)
}

func deleteLink(name string) {
	if l, err := netlink.LinkByName(name); err == nil {
		netlink.LinkDel(l)
	}
}

// setupLinks connects the namespace to the host: a veth (host side
// a.Veth, a.HostIP; inside eth0, a.SandboxIP, default route via the host)
// and lo up; for a VM also its tap, forwarding and NAT.
func (a *Attachment) setupLinks(tapUID int) error {
	const ones = 30
	ns, err := netns.GetFromPath(a.NetnsPath())
	if err != nil {
		return err
	}
	defer ns.Close()
	la := netlink.NewLinkAttrs()
	la.Name = a.Veth
	// One queue each way: by default a veth gets one per CPU, here 384
	// rx + 384 tx, each a kobject with its own uevents (~1500 per sandbox,
	// moving the peer into the namespace included), which kept udev busy
	// during bursts; a sandbox has no use for them.
	la.NumTxQueues, la.NumRxQueues = 1, 1
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: la, PeerName: "eth0", PeerNamespace: netlink.NsFd(int(ns)),
		PeerNumTxQueues: 1, PeerNumRxQueues: 1}); err != nil {
		return fmt.Errorf("veth %s: %w", a.Veth, err)
	}
	host, err := netlink.LinkByName(a.Veth)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(host, &netlink.Addr{IPNet: &net.IPNet{IP: a.HostIP, Mask: net.CIDRMask(ones, 32)}}); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(host); err != nil {
		return err
	}
	return inNetns(a.NetnsPath(), func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		for _, name := range []string{"lo", "eth0"} {
			l, err := h.LinkByName(name)
			if err != nil {
				return err
			}
			if name == "eth0" {
				if err := h.AddrAdd(l, &netlink.Addr{IPNet: &net.IPNet{IP: a.SandboxIP, Mask: net.CIDRMask(ones, 32)}}); err != nil {
					return err
				}
			}
			if err := h.LinkSetUp(l); err != nil {
				return err
			}
			if name == "eth0" {
				if err := h.RouteAdd(&netlink.Route{LinkIndex: l.Attrs().Index, Gw: a.HostIP}); err != nil {
					return fmt.Errorf("default route: %w", err)
				}
			}
		}
		if !a.VM {
			return nil
		}
		// A tap is made by opening /dev/net/tun: done here, children the
		// edge forks meanwhile would hold the queue until they exec, and
		// the VMM's own open of the single-queue tap would fail (EBUSY).
		// A process of its own opens it instead.
		if out, err := exec.Command("ip", "tuntap", "add", "dev", VMTap, "mode", "tap",
			"user", strconv.Itoa(tapUID), "group", strconv.Itoa(tapUID)).CombinedOutput(); err != nil {
			return fmt.Errorf("tap: %v: %s", err, out)
		}
		mac, _ := net.ParseMAC(VMTapMAC)
		l, err := h.LinkByName(VMTap)
		if err != nil {
			return err
		}
		h.LinkSetHardwareAddr(l, mac)
		if err := h.AddrAdd(l, &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP(VMGatewayIP), Mask: net.CIDRMask(VMPrefixLen, 32)}}); err != nil {
			return err
		}
		if err := h.LinkSetUp(l); err != nil {
			return err
		}
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0); err != nil {
			return err
		}
		return vmNAT(int(ns), a.HostIP)
	})
}

// vmNAT sets up the VM namespace's NAT: the guest's traffic leaves
// masqueraded as the sandbox; its DNS (to the gateway) goes to the host
// side, i.e. the edge's proxy.
func vmNAT(nsfd int, host net.IP) error {
	c, err := nftables.New(nftables.WithNetNSFd(nsfd))
	if err != nil {
		return err
	}
	t := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "opendsecvm"})
	pre := c.AddChain(&nftables.Chain{Name: "pre", Table: t, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest})
	post := c.AddChain(&nftables.Chain{Name: "post", Table: t, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource})
	for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
		c.AddRule(&nftables.Rule{Table: t, Chain: pre, Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(VMTap)},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip4(net.ParseIP(VMGatewayIP))},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 53}},
			&expr.Immediate{Register: 1, Data: ip4(host)},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1},
		}})
	}
	c.AddRule(&nftables.Rule{Table: t, Chain: post, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname("eth0")},
		&expr.Masq{},
	}})
	return c.Flush()
}
