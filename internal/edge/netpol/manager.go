// Package netpol gives sandboxes a network under a default-deny policy
// (spec §20; the paper enforces it with eBPF, this uses nftables). Each
// sandbox gets its own network namespace with a veth to the host and a /30
// of the edge's subnet. The host filters what it sends: allowed IPv4
// networks directly, allowed domains through the edge's DNS proxy, which
// resolves only those and lets the sandbox reach the addresses it returns.
// Rules can change while the sandbox runs.
//
// MicroVMs (spec §19.3) get the Firecracker clone-network layout inside
// their namespace: the same tap device and guest address in every VM,
// masqueraded to the sandbox's address, so snapshot copies keep a working
// network unchanged.
package netpol

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/edge/backend/linuxrt"
	"github.com/kernflux/opendsec/internal/ids"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// The microVM guest's side of its namespace (same in every VM).
const (
	VMTap       = "tap0"
	VMGatewayIP = "172.16.0.1" // the namespace's tap address; DNS goes here
	VMGuestIP   = "172.16.0.2"
	VMGuestMAC  = "06:00:ac:10:00:02"
	// The tap's own address is fixed too: a restored guest's ARP cache
	// holds the gateway of the VM it was snapshotted from.
	VMTapMAC    = "06:00:ac:10:00:01"
	VMPrefixLen = 30
)

const netnsDir = "/run/netns"

// Manager runs one edge's sandbox networking.
type Manager struct {
	edge    string
	table   string // nftables table
	prefix  string // host veth names (per edge: tables of edges on one host must not match each other's)
	nsPre   string // network namespace names
	pool    *net.IPNet
	slots   int
	dnsPort int
	dir     string // allocation records
	policy  *config.NetworkPolicy
	dns     *dnsProxy
	nl      *nl
	log     *slog.Logger

	mu      sync.Mutex
	byLease map[string]*Attachment
	bySlot  map[int]*Attachment
	byIP    map[string]*Attachment
}

// Attachment is one sandbox's network.
type Attachment struct {
	m         *Manager
	Lease     string `json:"lease"`
	Slot      int    `json:"slot"`
	Veth      string `json:"veth"`
	Netns     string `json:"netns"` // name under /run/netns
	HostIP    net.IP `json:"host_ip"`
	SandboxIP net.IP `json:"sandbox_ip"`
	VM        bool   `json:"vm,omitempty"`
	// Pid: a container's namespace is its init's, used through /proc (a
	// named one is a mount on the host: each new mount namespace copies
	// every mount, so thousands of them slow every sandbox start down).
	Pid int `json:"pid,omitempty"`

	mu      sync.Mutex
	pol     *policy
	learned map[string]learned // ip -> how it was learned
}

type learned struct {
	name string
	exp  time.Time
}

// NetnsPath is the namespace's path, for setns and the jailer's --netns.
func (a *Attachment) NetnsPath() string {
	if a.Pid > 0 {
		return fmt.Sprintf("/proc/%d/ns/net", a.Pid)
	}
	return filepath.Join(netnsDir, a.Netns)
}

// Nameserver is the resolver a container sandbox's resolv.conf names.
func (a *Attachment) Nameserver() string { return a.HostIP.String() }

// New starts the edge's networking: its nftables table and DNS proxy.
func New(edgeID string, ec config.EdgeNetwork, np *config.NetworkPolicy, stateDir string, log *slog.Logger) (*Manager, error) {
	subnet := ec.Subnet
	if subnet == "" {
		subnet = "10.88.0.0/16"
	}
	_, pool, err := net.ParseCIDR(subnet)
	if err != nil || pool.IP.To4() == nil {
		return nil, fmt.Errorf("network subnet %q: not an IPv4 network", subnet)
	}
	ones, _ := pool.Mask.Size()
	if ones > 28 {
		return nil, fmt.Errorf("network subnet %s is too small", subnet)
	}
	port := ec.DNSPort
	if port == 0 {
		port = 15353
	}
	for _, tool := range []string{"nft", "ip"} {
		if _, err := exec.LookPath(tool); err != nil {
			return nil, fmt.Errorf("sandbox networking needs %s", tool)
		}
	}
	h := fnv.New32a()
	h.Write([]byte(edgeID))
	tag := fmt.Sprintf("%04x", h.Sum32()&0xffff)
	m := &Manager{edge: edgeID, table: "opendsec_" + strings.ReplaceAll(edgeID, "-", "_"), prefix: "ds" + tag,
		nsPre: "opendsec-" + edgeID + "-", pool: pool, slots: 1 << (32 - ones - 2), dnsPort: port,
		dir: filepath.Join(stateDir, edgeID, "net"), policy: np, log: log,
		byLease: map[string]*Attachment{}, bySlot: map[int]*Attachment{}, byIP: map[string]*Attachment{}}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0); err != nil {
		return nil, fmt.Errorf("enable ip forwarding: %w", err)
	}
	if err := nft(m.baseRules()); err != nil {
		return nil, err
	}
	if m.nl, err = newNL(m.table); err != nil {
		return nil, err
	}
	upstream := np.UpstreamDNS
	if len(upstream) == 0 {
		upstream = hostResolvers()
	}
	if len(upstream) == 0 {
		return nil, fmt.Errorf("no upstream DNS: set network.upstream_dns")
	}
	if m.dns, err = startDNS(m, port, upstream); err != nil {
		return nil, err
	}
	return m, nil
}

// Close stops the DNS proxy. Sandbox networks stay (they outlive an edge
// restart); Cleanup removes them.
func (m *Manager) Close() {
	m.dns.close()
	m.nl.close()
}

func (m *Manager) Get(lease string) *Attachment {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.byLease[lease]
}

func (m *Manager) byAddr(ip net.IP) *Attachment {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.byIP[ip.String()]
}

// Validate checks rules without allocating anything.
func (m *Manager) Validate(rules map[string]bool) error {
	_, err := compile(m.policy, rules)
	return err
}

// Allocate reserves a network for lease under rules and installs its
// filtering; the backend then calls Setup.
func (m *Manager) Allocate(lease string, rules map[string]bool, vm bool) (*Attachment, error) {
	p, err := compile(m.policy, rules)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	if a := m.byLease[lease]; a != nil {
		m.mu.Unlock()
		return a, nil
	}
	h := fnv.New64a()
	h.Write([]byte(lease))
	sum := h.Sum64()
	slot := -1
	for i := 0; i < m.slots; i++ {
		n := 1 + int((sum+uint64(i))%uint64(m.slots-1)) // slot 0: the network's own address
		if m.bySlot[n] == nil {
			slot = n
			break
		}
	}
	if slot < 0 {
		m.mu.Unlock()
		return nil, rpcutil.Err(rpcutil.NoCapacity, "edge %s: no free sandbox address in %s", m.edge, m.pool)
	}
	base := binary.BigEndian.Uint32(m.pool.IP.To4()) + uint32(slot)*4
	a := &Attachment{m: m, Lease: lease, Slot: slot, Veth: fmt.Sprintf("%s%08x", m.prefix, uint32(sum)),
		Netns: m.nsPre + lease, HostIP: u32IP(base + 1), SandboxIP: u32IP(base + 2), VM: vm, pol: p,
		learned: map[string]learned{}}
	m.register(a)
	m.mu.Unlock()
	if err := linuxrt.WriteJSON(filepath.Join(m.dir, lease+".json"), a); err != nil {
		m.Release(lease)
		return nil, err
	}
	if err := m.nl.setSlot(a, p, nil, true); err != nil {
		m.Release(lease)
		return nil, fmt.Errorf("nftables: %w", err)
	}
	return a, nil
}

func (m *Manager) register(a *Attachment) {
	m.byLease[a.Lease], m.bySlot[a.Slot], m.byIP[a.SandboxIP.String()] = a, a, a
}

func u32IP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}

// Setup creates the sandbox's namespace and links: pid > 0 adopts the
// namespace of that process (a container's init); else a new one is made
// (a microVM, whose jailer then joins it), holding the VM's tap, owned by
// tapUID.
func (a *Attachment) Setup(pid, tapUID int) error {
	if pid > 0 {
		a.Pid = pid
		if err := linuxrt.WriteJSON(filepath.Join(a.m.dir, a.Lease+".json"), a); err != nil {
			return err
		}
	} else if err := newNetns(a.Netns, 0); err != nil {
		return fmt.Errorf("namespace: %w", err)
	}
	return a.setupLinks(tapUID)
}

// Rules replaces the sandbox's rules: denials apply at once, to new
// connections and DNS lookups; addresses learned for domains still allowed
// stay reachable. The kernel goes first, in one transaction: if it refuses
// the rules, nothing changes, and the DNS proxy keeps answering under the
// rules the kernel still enforces.
func (a *Attachment) Rules(rules map[string]bool) error {
	p, err := compile(a.m.policy, rules)
	if err != nil {
		return err
	}
	a.mu.Lock()
	keep := map[int]map[string]time.Time{}
	for ip, l := range a.learned {
		anyPort, ks := p.learnSets(l.name)
		if !anyPort && len(ks) == 0 {
			continue
		}
		if anyPort {
			ks = append(ks, -1)
		}
		for _, k := range ks {
			if keep[k] == nil {
				keep[k] = map[string]time.Time{}
			}
			keep[k][ip] = l.exp
		}
	}
	a.mu.Unlock()
	if err := a.m.nl.setSlot(a, p, learnedSets(keep), false); err != nil {
		return err
	}
	a.mu.Lock()
	for ip, l := range a.learned { // those learned meanwhile included
		if anyPort, ks := p.learnSets(l.name); !anyPort && len(ks) == 0 {
			delete(a.learned, ip)
		}
	}
	a.pol = p
	a.mu.Unlock()
	return nil
}

func learnedSets(m map[int]map[string]time.Time) []learnedSet {
	var out []learnedSet
	for k, ips := range m {
		out = append(out, learnedSet{k: k, ips: ips})
	}
	return out
}

func (a *Attachment) current() *policy {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pol
}

// learn lets the sandbox reach ips (resolved from name) for ttl.
func (a *Attachment) learn(name string, ips []net.IP, ttl time.Duration) error {
	ttl = min(max(ttl, 5*time.Minute), learnIdle)
	exp := time.Now().Add(ttl)
	add := map[string]time.Time{}
	a.mu.Lock()
	for _, ip := range ips {
		k := ip.String()
		if l, ok := a.learned[k]; ok && l.name == name && l.exp.Sub(time.Now()) > ttl/2 {
			continue
		}
		a.learned[k] = learned{name: name, exp: exp}
		add[k] = exp
	}
	anyPort, ks := a.pol.learnSets(name)
	a.mu.Unlock()
	if len(add) == 0 {
		return nil
	}
	// Into each set whose targets cover name: the any-port one and the
	// port-limited ones (spec §29.2).
	if anyPort {
		ks = append(ks, -1)
	}
	var sets []learnedSet
	for _, k := range ks {
		sets = append(sets, learnedSet{k: k, ips: add})
	}
	return a.m.nl.learn(a.Slot, sets)
}

// Release removes the sandbox's network.
func (m *Manager) Release(lease string) {
	m.mu.Lock()
	a := m.byLease[lease]
	if a != nil {
		delete(m.byLease, lease)
		delete(m.bySlot, a.Slot)
		delete(m.byIP, a.SandboxIP.String())
	}
	m.mu.Unlock()
	if a == nil {
		return
	}
	m.teardown(a.Slot, a.Veth, a.SandboxIP, a.Netns)
	os.Remove(filepath.Join(m.dir, lease+".json"))
}

func (m *Manager) teardown(slot int, veth string, ip net.IP, netns string) {
	deleteNetns(netns)
	deleteLink(veth)
	m.nl.removeSlot(slot, veth, ip)
}

// Restore takes back the networks of sandboxes a previous edge process
// left running (lease -> current rules) and removes all others: records,
// namespaces and slot chains.
func (m *Manager) Restore(keep map[string]map[string]bool) {
	ents, _ := os.ReadDir(m.dir)
	for _, e := range ents {
		lease, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		a := &Attachment{m: m, learned: map[string]learned{}}
		err := linuxrt.ReadJSON(filepath.Join(m.dir, e.Name()), a)
		rules, kept := keep[lease]
		if err == nil && kept {
			if a.pol, err = compile(m.policy, rules); err == nil {
				m.mu.Lock()
				m.register(a)
				m.mu.Unlock()
				err = m.nl.setSlot(a, a.pol, nil, true)
			}
			if err == nil {
				continue
			}
			m.log.Warn("netpol: restore", "lease", lease, "err", err)
		}
		if a.Slot > 0 {
			m.teardown(a.Slot, a.Veth, a.SandboxIP, a.Netns)
		}
		os.Remove(filepath.Join(m.dir, e.Name()))
	}
	// Namespaces and chains without a record.
	nss, _ := os.ReadDir(netnsDir)
	for _, e := range nss {
		if lease, ok := strings.CutPrefix(e.Name(), m.nsPre); ok && ids.ValidLease(lease) && m.Get(lease) == nil {
			deleteNetns(e.Name())
		}
	}
	if slots, err := m.nl.slots(); err == nil {
		m.mu.Lock()
		var stale []int
		for n := range slots {
			if m.bySlot[n] == nil {
				stale = append(stale, n)
			}
		}
		m.mu.Unlock()
		for _, n := range stale {
			m.nl.removeSlot(n, "", nil)
		}
	}
}

// Cleanup removes every sandbox network and the edge's table (edge shutdown
// with its sandboxes stopped).
func (m *Manager) Cleanup() {
	m.mu.Lock()
	var leases []string
	for l := range m.byLease {
		leases = append(leases, l)
	}
	m.mu.Unlock()
	for _, l := range leases {
		m.Release(l)
	}
	m.Restore(nil)
	nft(fmt.Sprintf("delete table inet %s\n", m.table))
}

func hostResolvers() []string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" && net.ParseIP(f[1]) != nil {
			out = append(out, net.JoinHostPort(f[1], "53"))
		}
	}
	return out
}
