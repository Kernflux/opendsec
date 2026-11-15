package netpol

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// A caller's own rules name private and reserved addresses only in the
// projects the configuration lists; rule sets and default rules do for all.
func TestCheckPrivate(t *testing.T) {
	m := &Manager{policy: &config.NetworkPolicy{
		RuleSets:            map[string][]string{"db": {"10.30.0.10:5432/tcp"}},
		DefaultRules:        map[string]bool{"10.40.0.0/16": true},
		PrivateRuleProjects: []string{"root/infra"},
	}}
	for _, k := range []string{"10.0.0.0/8", "10.1.2.3", "169.254.169.254:80/tcp", "192.168.0.48:2049", "0.0.0.0/0", "127.0.0.1", "8.0.0.0/5"} {
		err := m.CheckPrivate("root/team", map[string]bool{k: true}, nil)
		if rpcutil.Reason(err) != rpcutil.Forbidden {
			t.Errorf("%s: %v", k, err)
		}
		if err := m.CheckPrivate("root/infra/sub", map[string]bool{k: true}, nil); err != nil {
			t.Errorf("%s in an allowed project: %v", k, err)
		}
		if err := m.CheckPrivate("root/team", map[string]bool{k: false}, nil); err != nil {
			t.Errorf("%s taken back: %v", k, err)
		}
		if err := m.CheckPrivate("root/team", map[string]bool{k: true}, map[string]bool{k: true}); err != nil {
			t.Errorf("%s, which the sandbox had: %v", k, err)
		}
	}
	for _, k := range []string{"*", "*:443", "pypi.org", "203.0.113.0/24", "8.8.8.8:53/udp", "db", "10.40.0.0/16", "internal.example.com"} {
		if err := m.CheckPrivate("root/team", map[string]bool{k: true}, nil); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	if err := m.CheckPrivate("root/infrastructure", map[string]bool{"10.0.0.0/8": true}, nil); err == nil {
		t.Error("a project whose name only starts like an allowed one")
	}
}

// A sandbox learns at most dnsMaxLearned addresses: expired ones make
// room, else new ones are refused, and nothing half-learned stays.
func TestLearnedFull(t *testing.T) {
	m := &Manager{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a := &Attachment{m: m, pol: &policy{}, learned: map[string]learned{}}
	soon := time.Now().Add(time.Hour)
	for i := 0; i < dnsMaxLearned; i++ {
		a.learned[fmt.Sprintf("198.51.%d.%d", i>>8, i&255)] = learned{name: "x.example", exp: soon}
	}
	ips := []net.IP{net.IPv4(203, 0, 113, 1).To4(), net.IPv4(203, 0, 113, 2).To4()}
	if err := a.learn("y.example", ips, time.Minute); err != errLearnedFull {
		t.Fatalf("full: %v", err)
	}
	if len(a.learned) != dnsMaxLearned || !a.full {
		t.Fatalf("%d learned, full %v", len(a.learned), a.full)
	}
	// One already learned is refreshed all the same (it takes no room);
	// with the others expired there is room again. (No kernel here: the
	// calls that would reach it are not made in this test.)
	for k, l := range a.learned {
		l.exp = time.Now().Add(-time.Second)
		a.learned[k] = l
	}
	func() {
		defer func() { recover() }() // nl is nil: learn got past the limit
		a.learn("y.example", ips, time.Minute)
	}()
	if len(a.learned) != 2 || a.full {
		t.Fatalf("%d learned after the others expired, full %v", len(a.learned), a.full)
	}
}

func TestRefuse(t *testing.T) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	var p dnsmessage.Parser
	h, err := p.Start(refuse(q, dnsmessage.RCodeServerFailure))
	if err != nil || h.ID != 7 || !h.Response || h.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("%+v %v", h, err)
	}
	if refuse([]byte{1, 2}, dnsmessage.RCodeRefused) != nil {
		t.Fatal("answered garbage")
	}
}
