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
