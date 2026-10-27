package fleet

import (
	"fmt"
	"strings"
	"testing"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
)

func edgeNodes(perDomain map[string]int) []*pb.FleetNode {
	var out []*pb.FleetNode
	for d, n := range perDomain {
		for i := 0; i < n; i++ {
			out = append(out, &pb.FleetNode{Name: fmt.Sprintf("%s-%02d", d, i), Domain: d, Roles: map[string]string{"edge": fmt.Sprintf("%s-%02d", d, i)}})
		}
	}
	return out
}

func TestPlanBatches(t *testing.T) {
	nodes := edgeNodes(map[string]int{"az1": 30, "az2": 30, "az3": 40})
	nodes = append(nodes, &pb.FleetNode{Name: "ctl1", Domain: "az1", Roles: map[string]string{"iam": "0", "edge": "ctl1"}},
		&pb.FleetNode{Name: "ctl2", Domain: "az2", Roles: map[string]string{"apiserver": "0"}})
	st := Strategy(nil, 100)
	if st.Batch != 5 || st.MaxPerDomain != 2 || st.Canary != 1 || st.BakeS != 300 {
		t.Fatalf("defaults: %+v", st)
	}
	steps, batches := Plan(nodes, st)
	if len(steps) != len(nodes) {
		t.Fatalf("%d steps for %d nodes", len(steps), len(nodes))
	}
	perBatch := map[int32]map[string]int{}
	count := map[int32]int{}
	seen := map[string]bool{}
	for _, s := range steps {
		if seen[s.Node] {
			t.Fatalf("%s planned twice", s.Node)
		}
		seen[s.Node] = true
		if s.Node == "ctl1" || s.Node == "ctl2" {
			if s.Batch != -1 {
				t.Fatalf("control node %s in batch %d", s.Node, s.Batch)
			}
			continue
		}
		d := s.Node[:3]
		if perBatch[s.Batch] == nil {
			perBatch[s.Batch] = map[string]int{}
		}
		perBatch[s.Batch][d]++
		count[s.Batch]++
	}
	if count[0] != 1 {
		t.Fatalf("canary batch has %d nodes", count[0])
	}
	for b := int32(1); b < int32(batches); b++ {
		if count[b] == 0 || count[b] > 5 {
			t.Fatalf("batch %d has %d nodes", b, count[b])
		}
		for d, c := range perBatch[b] {
			if c > 2 {
				t.Fatalf("batch %d has %d nodes of %s", b, c, d)
			}
		}
	}
	// 99 edge-only nodes, canary 1: the domain cap leaves 2+2+1 per batch
	// while three domains have nodes, then only the cap's worth of the last.
	if batches < 1+98/5 {
		t.Fatalf("%d batches", batches)
	}
}

func TestPlanSingleDomainNoCap(t *testing.T) {
	steps, batches := Plan(edgeNodes(map[string]int{"": 10}), Strategy(&pb.FleetStrategy{Batch: 4, Canary: -1}, 10))
	if batches != 3 {
		t.Fatalf("10 nodes in batches of 4 without a canary: %d batches", batches)
	}
	if steps[0].Batch != 0 || steps[3].Batch != 0 || steps[4].Batch != 1 {
		t.Fatalf("one domain is not capped: %v", steps)
	}
}

func TestSelects(t *testing.T) {
	n := &pb.FleetNode{Name: "a", Domain: "az1", Roles: map[string]string{"edge": "a"}, Labels: map[string]string{"gpu": "1"}}
	for _, c := range []struct {
		sel  *pb.FleetSelector
		want bool
	}{
		{nil, true},
		{&pb.FleetSelector{Roles: []string{"iam", "edge"}}, true},
		{&pb.FleetSelector{Roles: []string{"iam"}}, false},
		{&pb.FleetSelector{Domains: []string{"az2"}}, false},
		{&pb.FleetSelector{Labels: map[string]string{"gpu": "1"}}, true},
		{&pb.FleetSelector{Labels: map[string]string{"gpu": "0"}}, false},
		{&pb.FleetSelector{Nodes: []string{"b"}}, false},
	} {
		if got := Selects(c.sel, n); got != c.want {
			t.Errorf("%v: %v", c.sel, got)
		}
	}
}

// TestDeployed: a node's health counts the roles it was last applied
// with, not roles added since (which deploying would otherwise wait on:
// each node's rollout waits on the health of the others).
func TestDeployed(t *testing.T) {
	n := &pb.FleetNode{Name: "a", Roles: map[string]string{"apiserver": "0", "e2b": "0", "edge": "e1"}}
	if d := deployed(n); d != n {
		t.Fatal("a node recorded before deployed_roles: all its roles count")
	}
	n.DeployedRoles = []string{"apiserver", "edge", "watcher"} // e2b added since; watcher removed since
	d := deployed(n)
	if len(d.Roles) != 2 || d.Roles["apiserver"] != "0" || d.Roles["edge"] != "e1" {
		t.Fatalf("deployed roles %v", d.Roles)
	}
	var units []string
	for _, u := range nodeUnits(d, map[string]int{"apiserver": 9463, "e2b": 9467}) {
		units = append(units, u.Unit)
	}
	if strings.Join(units, " ") != "opendsec-apiserver@0.service opendsec-edge.service" {
		t.Fatalf("units %v", units)
	}
	if got := strings.Join(rolesOf(n), ","); got != "apiserver=0,e2b=0,edge=e1" {
		t.Fatalf("rolesOf %s", got)
	}
	// Recorded with ids: a role renumbered since counts with its old id
	// (its new unit runs only once deployed), and one removed since still
	// counts (it runs until then).
	n.Roles = map[string]string{"apiserver": "0", "e2b": "1"}
	n.DeployedRoles = []string{"apiserver=0", "e2b=0", "edge=e1"}
	d = deployed(n)
	if len(d.Roles) != 3 || d.Roles["e2b"] != "0" || d.Roles["edge"] != "e1" || d.Name != "a" {
		t.Fatalf("deployed roles %v", d.Roles)
	}
	if n.Roles["e2b"] != "1" {
		t.Fatal("deployed changed the node")
	}
}
