package netpol

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"

	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

var testPolicy = &config.NetworkPolicy{
	RuleSets: map[string][]string{
		"pypi": {"pypi.org", "files.pythonhosted.org"},
		"dns":  {"1.1.1.1", "9.9.9.0/24"},
	},
	DefaultRules: map[string]bool{"dns": true},
}

func TestCompile(t *testing.T) {
	p, err := compile(testPolicy, map[string]bool{"pypi": true, "*.Example.COM": true, "10.1.0.0/16": true})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"pypi.org": true, "www.pypi.org": true, "files.pythonhosted.org": true,
		"example.com": true, "a.b.example.com": true, "evilpypi.org": false, "pypi.org.evil.net": false, "npmjs.org": false} {
		if p.allowsName(name) != want {
			t.Errorf("allowsName(%s) = %v", name, !want)
		}
	}
	if len(p.nets) != 3 || p.all { // 1.1.1.1/32, 9.9.9.0/24 (defaults), 10.1.0.0/16
		t.Errorf("nets %v all %v", p.nets, p.all)
	}
	// false takes a default back; "*" allows everything.
	p, _ = compile(testPolicy, map[string]bool{"dns": false, AllowAll: true})
	if len(p.nets) != 0 || !p.all || !p.allowsName("anything.example") {
		t.Errorf("%+v", p)
	}
	for _, bad := range []string{"no-such-set", "1.2.3.4/40", "::1", "a..b", "-x.com"} {
		if _, err := compile(testPolicy, map[string]bool{bad: true}); rpcutil.Reason(err) != rpcutil.Invalid {
			t.Errorf("rule %q: %v", bad, err)
		}
	}
	// A denied unknown name is no error (nothing to take back).
	if _, err := compile(testPolicy, map[string]bool{"no-such-set": false}); err != nil {
		t.Error(err)
	}
}

// TestCompilePorts (spec §29.2): entries limited to ports and protocols.
func TestCompilePorts(t *testing.T) {
	pol := &config.NetworkPolicy{RuleSets: map[string][]string{"db": {"10.0.0.0/8:5432/tcp", "10.0.0.0/8:6379/tcp"}}}
	p, err := compile(pol, map[string]bool{"pypi.org:443": true, "db": true, "*:443/tcp": true, "1.1.1.1:53/udp": true,
		"x.example.com:8000-8080": true, "y.example.com": true})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range p.limited {
		got = append(got, fmt.Sprintf("%s all=%v domains=%v nets=%d", l.ports, l.all, l.domains, len(l.nets)))
	}
	want := []string{"443 all=false domains=[pypi.org] nets=0", "443/tcp all=true domains=[] nets=0",
		"53/udp all=false domains=[] nets=1", "5432/tcp all=false domains=[] nets=1", "6379/tcp all=false domains=[] nets=1",
		"8000-8080 all=false domains=[x.example.com] nets=0"}
	if strings.Join(got, "; ") != strings.Join(want, "; ") {
		t.Errorf("limited:\n got %v\nwant %v", got, want)
	}
	if p.all || len(p.nets) != 0 || len(p.domains) != 1 {
		t.Errorf("any-port targets: %+v", p.targets)
	}
	// Names resolve when some entry covers them; their addresses go to the
	// sets of the entries that do.
	for name, want := range map[string]string{"pypi.org": "false [0 1]", "x.example.com": "false [1 5]",
		"y.example.com": "true [1]", "files.pythonhosted.org": "false [1]"} {
		a, ks := p.learnSets(name)
		if g := fmt.Sprint(a, " ", ks); g != want {
			t.Errorf("learnSets(%s) = %s, want %s", name, g, want)
		}
	}
	for _, bad := range []string{"x.com:0", "x.com:70000", "x.com:443/icmp", "x.com:9-1", "x.com:", "x.com:a",
		"10.0.0.0/33:80", "::1"} {
		if _, err := compile(pol, map[string]bool{bad: true}); rpcutil.Reason(err) != rpcutil.Invalid {
			t.Errorf("rule %q: %v", bad, err)
		}
	}
}

// inNetns runs fn on a thread in the network namespace at path: sockets fn
// opens belong to it.
func inNS(t *testing.T, path string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread() // never unlocked: the thread exits with the goroutine
		f, err := os.Open(path)
		if err != nil {
			t.Error(err)
			return
		}
		defer f.Close()
		if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
			t.Error(err)
			return
		}
		fn()
	}()
	<-done
}

// lookup resolves name's A records through a's DNS proxy, on the calling
// thread (net.Resolver would query from another goroutine, i.e. maybe
// another namespace).
func lookup(a *Attachment, name string) ([]string, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	c, err := net.Dial("udp", net.JoinHostPort(a.Nameserver(), "53"))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	var p dnsmessage.Parser
	h, err := p.Start(buf[:n])
	if err != nil {
		return nil, err
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("lookup %s: %v", name, h.RCode)
	}
	ips, _ := answerA(buf[:n])
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("lookup %s: no address", name)
	}
	return out, nil
}

func dial(addr string) error {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err == nil {
		c.Close()
	}
	return err
}

// TestPolicy (root, nftables, internet; OPENDSEC_NET_TESTS=1: it enables IPv4
// forwarding on the host): default deny, domains through the DNS proxy,
// CIDRs, isolation from the host and other sandboxes, live rule changes,
// restore after a restart.
func TestPolicy(t *testing.T) {
	if os.Getenv("OPENDSEC_NET_TESTS") == "" || os.Geteuid() != 0 {
		t.Skip("set OPENDSEC_NET_TESTS=1 (as root)")
	}
	state := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ec := config.EdgeNetwork{Enabled: true, Subnet: "10.87.0.0/24", DNSPort: 15399}
	m, err := New("t-net", ec, testPolicy, state, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Cleanup(); m.Close() })
	a, err := m.Allocate("aaaaaaaaaaaaaaaaaaaaaaaaaa", map[string]bool{"pypi": true}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Setup(0, 0); err != nil {
		t.Fatal(err)
	}
	b, err := m.Allocate("bbbbbbbbbbbbbbbbbbbbbbbbbb", map[string]bool{AllowAll: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Setup(0, 0); err != nil {
		t.Fatal(err)
	}
	hostIPs, err := net.LookupHost("example.com")
	if err != nil {
		t.Fatal(err)
	}
	example := net.JoinHostPort(hostIPs[0], "443")
	var pypi string
	inNS(t, a.NetnsPath(), func() {
		ips, err := lookup(a, "pypi.org")
		if err != nil || len(ips) == 0 {
			t.Errorf("allowed domain: %v %v", ips, err)
			return
		}
		pypi = net.JoinHostPort(ips[0], "443")
		if err := dial(pypi); err != nil {
			t.Errorf("connect to an allowed domain: %v", err)
		}
		if ips, err := lookup(a, "example.com"); err == nil || !strings.Contains(err.Error(), "RCodeNameError") {
			t.Errorf("denied domain resolved: %v %v", ips, err)
		}
		if err := dial(example); err == nil {
			t.Error("connected to a denied address")
		}
		if err := dial("1.0.0.1:443"); err == nil {
			t.Error("connected to an address no rule allows")
		}
		if err := dial("1.1.1.1:443"); err != nil {
			t.Errorf("connect to a default rule's address: %v", err)
		}
		// The host (other than its DNS proxy) and other sandboxes.
		if err := dial(net.JoinHostPort(a.HostIP.String(), "22")); err == nil {
			t.Error("reached the host's sshd")
		}
	})
	l := listenIn(t, b, "8080")
	defer l.Close()
	inNS(t, a.NetnsPath(), func() {
		if err := dial(net.JoinHostPort(b.SandboxIP.String(), "8080")); err == nil {
			t.Error("reached another sandbox")
		}
	})
	inNS(t, b.NetnsPath(), func() {
		// "*": any public destination, but no private or link-local ones.
		if _, err := lookup(b, "example.com"); err != nil {
			t.Errorf("allow-all lookup: %v", err)
		}
		if err := dial(example); err != nil {
			t.Errorf("allow-all connect: %v", err)
		}
		if err := dial("169.254.169.254:80"); err == nil {
			t.Error("reached the metadata address")
		}
		if ips, _ := lookup(b, "localhost.localdomain"); len(ips) > 0 {
			for _, ip := range ips {
				if ip != "127.0.0.1" && dial(net.JoinHostPort(ip, "22")) == nil {
					t.Error("reached a private address")
				}
			}
		}
	})
	// Live changes: allow example.com, take pypi back.
	if err := a.Rules(map[string]bool{"example.com": true}); err != nil {
		t.Fatal(err)
	}
	inNS(t, a.NetnsPath(), func() {
		if _, err := lookup(a, "pypi.org"); err == nil {
			t.Error("revoked domain still resolves")
		}
		if err := dial(pypi); err == nil {
			t.Error("revoked domain's address still reachable")
		}
		if _, err := lookup(a, "example.com"); err != nil {
			t.Errorf("newly allowed domain: %v", err)
		}
		if err := dial(example); err != nil {
			t.Errorf("connect to a newly allowed domain: %v", err)
		}
	})
	// A restarted edge keeps a's network and drops b's.
	m.Close()
	m2, err := New("t-net", ec, testPolicy, state, log)
	if err != nil {
		t.Fatal(err)
	}
	m = m2
	m.Restore(map[string]map[string]bool{a.Lease: {"example.com": true}})
	if _, err := os.Stat(b.NetnsPath()); err == nil {
		t.Error("unkept sandbox's namespace survived")
	}
	a2 := m.Get(a.Lease)
	if a2 == nil || !a2.SandboxIP.Equal(a.SandboxIP) {
		t.Fatalf("restored attachment %+v", a2)
	}
	inNS(t, a2.NetnsPath(), func() {
		if _, err := lookup(a2, "example.com"); err != nil {
			t.Errorf("after restore: %v", err)
		}
		if err := dial(example); err != nil {
			t.Errorf("connect after restore: %v", err)
		}
	})
	m.Release(a.Lease)
	if _, err := os.Stat(a.NetnsPath()); err == nil {
		t.Error("released namespace survived")
	}
	if slots, _ := m.nl.slots(); len(slots) != 0 {
		t.Errorf("slot chains left: %v", slots)
	}
}

// TestPolicyPorts (root, nftables, internet; OPENDSEC_NET_TESTS=1; spec
// §29.2): entries limited to a port and protocol, for a domain and for
// "*", changed live; their sets go when no longer used.
func TestPolicyPorts(t *testing.T) {
	if os.Getenv("OPENDSEC_NET_TESTS") == "" || os.Geteuid() != 0 {
		t.Skip("set OPENDSEC_NET_TESTS=1 (as root)")
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ec := config.EdgeNetwork{Enabled: true, Subnet: "10.86.0.0/24", DNSPort: 15398}
	m, err := New("t-port", ec, testPolicy, t.TempDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Cleanup(); m.Close() })
	attach := func(lease string, rules map[string]bool) *Attachment {
		a, err := m.Allocate(lease, rules, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Setup(0, 0); err != nil {
			t.Fatal(err)
		}
		return a
	}
	limitedSets := func(slot int) (n int) {
		sets, err := m.nl.conn.GetSets(m.nl.table)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range sets {
			if _, ok := isLimitedSet(s.Name, slot); ok {
				n++
			}
		}
		return n
	}
	hostIPs, err := net.LookupHost("example.com")
	if err != nil {
		t.Fatal(err)
	}
	ex443, ex80 := net.JoinHostPort(hostIPs[0], "443"), net.JoinHostPort(hostIPs[0], "80")
	c := attach("cccccccccccccccccccccccccc", map[string]bool{"dns": false, "example.com:443/tcp": true})
	d := attach("dddddddddddddddddddddddddd", map[string]bool{"dns": false, "*:443/tcp": true})
	inNS(t, c.NetnsPath(), func() {
		if _, err := lookup(c, "example.com"); err != nil {
			t.Errorf("domain allowed on a port does not resolve: %v", err)
		}
		if err := dial(ex443); err != nil {
			t.Errorf("allowed port: %v", err)
		}
		if err := dial(ex80); err == nil {
			t.Error("reached a port the rule does not allow")
		}
		if err := dial("1.1.1.1:443"); err == nil {
			t.Error("reached an address no rule allows")
		}
	})
	inNS(t, d.NetnsPath(), func() {
		if _, err := lookup(d, "example.com"); err != nil {
			t.Errorf(`"*:443/tcp" lookup: %v`, err)
		}
		if err := dial("1.0.0.1:443"); err != nil {
			t.Errorf(`"*:443/tcp" to a public address: %v`, err)
		}
		if err := dial("1.0.0.1:80"); err == nil {
			t.Error(`"*:443/tcp" reached port 80`)
		}
		if err := dial("169.254.169.254:443"); err == nil {
			t.Error(`"*:443/tcp" reached the metadata address`)
		}
	})
	// Live: move c to port 80, then to any port; the 443 set goes.
	if err := c.Rules(map[string]bool{"dns": false, "example.com:80/tcp": true}); err != nil {
		t.Fatal(err)
	}
	inNS(t, c.NetnsPath(), func() {
		lookup(c, "example.com")
		if err := dial(ex443); err == nil {
			t.Error("port taken back still reachable")
		}
		if err := dial(ex80); err != nil {
			t.Errorf("newly allowed port: %v", err)
		}
	})
	if err := c.Rules(map[string]bool{"dns": false, "example.com": true}); err != nil {
		t.Fatal(err)
	}
	if n := limitedSets(c.Slot); n != 0 {
		t.Errorf("%d port-limited sets left after the rules dropped ports", n)
	}
	inNS(t, c.NetnsPath(), func() {
		lookup(c, "example.com")
		if dial(ex443) != nil || dial(ex80) != nil {
			t.Error("any-port domain not reachable on both ports")
		}
	})
	m.Release(d.Lease)
	if n := limitedSets(d.Slot); n != 0 {
		t.Errorf("%d port-limited sets left after release", n)
	}
}

func listenIn(t *testing.T, a *Attachment, port string) net.Listener {
	var l net.Listener
	inNS(t, a.NetnsPath(), func() {
		var err error
		if l, err = net.Listen("tcp", net.JoinHostPort(a.SandboxIP.String(), port)); err != nil {
			t.Fatal(err)
		}
	})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l
}

// TestSlotScale (OPENDSEC_NET_BENCH=1, root): the cost of adding a sandbox's
// filtering as the edge's table grows.
func TestSlotScale(t *testing.T) {
	if os.Getenv("OPENDSEC_NET_BENCH") == "" || os.Geteuid() != 0 {
		t.Skip("set OPENDSEC_NET_BENCH=1 (as root)")
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := New("t-scale", config.EdgeNetwork{Enabled: true, Subnet: "10.84.0.0/16", DNSPort: 15396}, testPolicy, t.TempDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Cleanup(); m.Close() })
	n := 0
	for _, target := range []int{1, 500, 1000, 2000, 5000} {
		var last, worst time.Duration
		from, stage := n, time.Now()
		for ; n < target; n++ {
			start := time.Now()
			if _, err := m.Allocate(fmt.Sprintf("%026d", n), map[string]bool{"pypi": true}, false); err != nil {
				t.Fatal(err)
			}
			last = time.Since(start)
			worst = max(worst, last)
		}
		t.Logf("%d sandboxes: allocating one took %v (stage mean %v, worst %v)", n, last,
			time.Since(stage)/time.Duration(max(1, n-from)), worst)
	}
	start := time.Now()
	for i := 0; i < 100; i++ {
		m.Release(fmt.Sprintf("%026d", n-1-i))
	}
	t.Logf("%d sandboxes: releasing one took %v", n, time.Since(start)/100)
	start = time.Now()
	m.Cleanup()
	t.Logf("cleanup of %d took %v", n-100, time.Since(start))
}

func TestParseLimitedSet(t *testing.T) {
	for _, c := range []struct {
		name    string
		slot, k int
		ok      bool
	}{
		{"a12p0", 12, 0, true}, {"n7p3", 7, 3, true},
		{"a12", 0, 0, false}, {"n12", 0, 0, false}, {"s3", 0, 0, false}, {"sb", 0, 0, false},
		{"private", 0, 0, false}, {"a1p", 0, 0, false}, {"ap1", 0, 0, false}, {"a01p1", 0, 0, false},
		{"a1p2x", 0, 0, false}, {"a-1p2", 0, 0, false},
	} {
		slot, k, ok := parseLimitedSet(c.name)
		if ok != c.ok || (ok && (slot != c.slot || k != c.k)) {
			t.Errorf("parseLimitedSet(%q) = %d, %d, %v; want %d, %d, %v", c.name, slot, k, ok, c.slot, c.k, c.ok)
		}
	}
	if k, ok := isLimitedSet("a5p2", 5); !ok || k != 2 {
		t.Error("isLimitedSet(a5p2, 5)")
	}
	if _, ok := isLimitedSet("a5p2", 6); ok {
		t.Error("isLimitedSet(a5p2, 6)")
	}
}
