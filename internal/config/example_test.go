package config

import (
	"strings"
	"testing"
)

// The example in deploy/ stays loadable.
func TestExampleConfig(t *testing.T) {
	c, err := Load("../../deploy/opendsec.example.json")
	if err != nil {
		t.Fatal(err)
	}
	e, err := c.Edge("e003")
	if err != nil {
		t.Fatal(err)
	}
	if !e.Network.Enabled || e.Backends["fncall"].WarmPool["root/tools:1"] != 32 || e.Backends["fullvm"].Runtime != "qemu" ||
		e.PausedMemCharge == nil || c.Network.RuleSets["pypi"] == nil {
		t.Fatalf("example edge e003: %+v", e)
	}
}

func TestEdgeZoneValidated(t *testing.T) {
	c := &Cluster{ServiceToken: "x", Edges: []Edge{{ID: "e1", Addr: "127.0.0.1:1", Zone: "az1"}}}
	c.Defaults()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "zone") {
		t.Fatalf("zone az1 accepted: %v", err)
	}
}
