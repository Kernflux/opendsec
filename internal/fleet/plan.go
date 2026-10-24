package fleet

import (
	"fmt"
	"math"
	"sort"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
)

// Roles a node can carry, in the order a node's units restart (spec §28.6).
var unitOrder = []string{"iam", "watcher", "apiserver", "e2b", "fleet", "edge"}

// controlRoles are the cluster-level components: their nodes are upgraded
// one at a time, before any edge batch.
var controlRoles = map[string]bool{"iam": true, "watcher": true, "apiserver": true, "e2b": true, "fleet": true}

func isControl(n *pb.FleetNode) bool {
	for r := range n.Roles {
		if controlRoles[r] {
			return true
		}
	}
	return false
}

// UnitName is the systemd unit of a role instance (deploy/systemd).
func UnitName(role, id string) string {
	if role == "edge" {
		return "opendsec-edge.service"
	}
	return fmt.Sprintf("opendsec-%s@%s.service", role, id)
}

// nodeUnits lists the node's units in restart order, with their readiness
// endpoints.
func nodeUnits(n *pb.FleetNode, ports map[string]int) []*pb.NodeUnit {
	var out []*pb.NodeUnit
	for _, r := range unitOrder {
		id, ok := n.Roles[r]
		if !ok {
			continue
		}
		u := &pb.NodeUnit{Unit: UnitName(r, id)}
		if p := ports[r]; p > 0 {
			u.Readyz = fmt.Sprintf("http://127.0.0.1:%d/readyz", p)
		}
		out = append(out, u)
	}
	return out
}

// Selects reports whether the selector picks node n.
func Selects(sel *pb.FleetSelector, n *pb.FleetNode) bool {
	if sel == nil {
		return true
	}
	if len(sel.Nodes) > 0 && !contains(sel.Nodes, n.Name) {
		return false
	}
	if len(sel.Domains) > 0 && !contains(sel.Domains, n.Domain) {
		return false
	}
	if len(sel.Roles) > 0 {
		any := false
		for _, r := range sel.Roles {
			_, has := n.Roles[r]
			any = any || has
		}
		if !any {
			return false
		}
	}
	for k, v := range sel.Labels {
		if n.Labels[k] != v {
			return false
		}
	}
	return true
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Strategy returns st with the defaults filled in for n non-control nodes.
func Strategy(st *pb.FleetStrategy, n int) *pb.FleetStrategy {
	out := &pb.FleetStrategy{}
	if st != nil {
		*out = pb.FleetStrategy{Canary: st.Canary, BakeS: st.BakeS, Batch: st.Batch, MaxPerDomain: st.MaxPerDomain,
			PauseS: st.PauseS, MaxFailures: st.MaxFailures, StepTimeoutS: st.StepTimeoutS}
	}
	if out.Canary == 0 {
		out.Canary = 1
	}
	if out.Canary < 0 { // explicitly none
		out.Canary = 0
	}
	if out.BakeS == 0 {
		out.BakeS = 300
	}
	if out.Batch <= 0 {
		out.Batch = int32(min(100, max(1, int(math.Ceil(0.05*float64(n))))))
	}
	if out.MaxPerDomain <= 0 {
		out.MaxPerDomain = max(1, out.Batch/2)
	}
	if out.PauseS == 0 {
		out.PauseS = 60
	}
	if out.PauseS < 0 {
		out.PauseS = 0
	}
	if out.BakeS < 0 {
		out.BakeS = 0
	}
	if out.MaxFailures < 0 {
		out.MaxFailures = 0
	}
	if out.StepTimeoutS <= 0 {
		out.StepTimeoutS = 600
	}
	return out
}

// Plan assigns the selected nodes to batches: control-plane nodes get batch
// -1 (upgraded one at a time, in the order chosen at run time); the others
// get batch 0 (the canary) and up, filled round-robin over failure domains
// with at most max_per_domain nodes of one domain per batch (when there is
// more than one domain), so no batch restarts many edges of one domain.
func Plan(nodes []*pb.FleetNode, st *pb.FleetStrategy) (steps []*pb.FleetStep, batches int) {
	byDomain := map[string][]string{}
	for _, n := range nodes {
		if isControl(n) {
			steps = append(steps, &pb.FleetStep{Node: n.Name, Batch: -1, Phase: "pending"})
			continue
		}
		byDomain[n.Domain] = append(byDomain[n.Domain], n.Name)
	}
	var domains []string
	for d, l := range byDomain {
		sort.Strings(l)
		domains = append(domains, d)
	}
	sort.Strings(domains)
	left := 0
	for _, l := range byDomain {
		left += len(l)
	}
	next := 0 // rotating start, so batches interleave domains
	take := func(size int, capPer int) []string {
		var b []string
		per := map[string]int{}
		for len(b) < size {
			progress := false
			for i := 0; i < len(domains) && len(b) < size; i++ {
				d := domains[(next+i)%len(domains)]
				if len(byDomain[d]) == 0 || per[d] >= capPer {
					continue
				}
				b = append(b, byDomain[d][0])
				byDomain[d] = byDomain[d][1:]
				per[d]++
				progress = true
			}
			if !progress {
				break
			}
		}
		if len(domains) > 0 {
			next = (next + 1) % len(domains)
		}
		return b
	}
	capPer := int(st.MaxPerDomain)
	if len(domains) <= 1 {
		capPer = math.MaxInt
	}
	batch := 0
	if st.Canary > 0 && left > 0 {
		for _, name := range take(int(st.Canary), math.MaxInt) {
			steps = append(steps, &pb.FleetStep{Node: name, Batch: 0, Phase: "pending"})
			left--
		}
		batch = 1
	}
	for left > 0 {
		b := take(int(st.Batch), capPer)
		if len(b) == 0 {
			break
		}
		for _, name := range b {
			steps = append(steps, &pb.FleetStep{Node: name, Batch: int32(batch), Phase: "pending"})
			left--
		}
		batch++
	}
	return steps, batch
}
