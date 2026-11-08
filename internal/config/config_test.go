package config

import (
	"strings"
	"testing"
)

func TestPlaceholderSecret(t *testing.T) {
	for tok, want := range map[string]bool{
		"dsk.admin.change-me-admin-secret": true,
		"dsk.admin.CHANGE-ME":              true,
		"dsk.admin.3f9c2a7e1b":             false,
		"":                                 false,
	} {
		if got := PlaceholderSecret(tok); got != want {
			t.Errorf("PlaceholderSecret(%q) = %v", tok, got)
		}
	}
}

func TestEdgeTemplateZone(t *testing.T) {
	c := &Cluster{ServiceToken: "dsk.svc.x", EdgeTemplate: &Edge{Zone: "local"}}
	c.Defaults()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "edge_template: zone") {
		t.Fatalf("zone local: %v", err)
	}
}

func TestBlockedPorts(t *testing.T) {
	b, err := BlockedPorts([]string{"25/tcp", " 465/tcp", "6660-6669", "53/udp"})
	if err != nil || len(b) != 4 || b[2] != (PortBlock{6660, 6669, ""}) || b[3].Proto != "udp" {
		t.Fatalf("%v %+v", err, b)
	}
	for _, bad := range []string{"0", "65536", "25/icmp", "x", "30-20", "25/"} {
		if _, err := BlockedPorts([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
