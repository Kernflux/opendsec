package netpol

import (
	"strings"
	"testing"

	"github.com/kernflux/opendsec/internal/config"
)

// Blocked ports come before the sandboxes' own chains, per protocol.
func TestBlockRules(t *testing.T) {
	b, err := config.BlockedPorts([]string{"25/tcp", "6660-6669/tcp", "53"})
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{table: "opendsec_e1", prefix: "ds1234", blocked: b}
	got := m.blockRules()
	for _, want := range []string{
		`add rule inet opendsec_e1 forward iifname "ds1234*" tcp dport 25 drop`,
		`add rule inet opendsec_e1 forward iifname "ds1234*" tcp dport 6660-6669 drop`,
		`add rule inet opendsec_e1 forward iifname "ds1234*" tcp dport 53 drop`,
		`add rule inet opendsec_e1 forward iifname "ds1234*" udp dport 53 drop`,
	} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "udp dport 25") {
		t.Errorf("25/tcp blocked udp too:\n%s", got)
	}
	base := m.baseRules()
	if i, j := strings.Index(base, "tcp dport 25 drop"), strings.Index(base, "vmap @sb"); i < 0 || j < i {
		t.Fatalf("blocked ports must come before the sandbox chains:\n%s", base)
	}
	if (&Manager{table: "t", prefix: "p"}).blockRules() != "" {
		t.Fatal("no blocked ports, no rules")
	}
}
