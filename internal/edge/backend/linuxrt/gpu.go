package linuxrt

import (
	"fmt"
	"sort"
	"sync"

	"github.com/kernflux/opendsec/internal/rpcutil"
)

// GPUs hands out a node's GPU devices to sandboxes (spec §22.2): exclusive
// sandboxes get whole devices; shared ones (gpu_mode "shared") a slot on a
// device no exclusive sandbox holds, up to slots sandboxes per device
// (time-sliced by the driver, or MPS if the node runs it). One per edge,
// shared by its container-runtime backends.
type GPUs struct {
	Devices []string // device nodes, e.g. /dev/nvidia0; index = position
	Extra   []string // nodes every GPU sandbox gets (/dev/nvidiactl, /dev/nvidia-uvm, ...)
	Mounts  []string // host paths bound read-only (driver libraries, nvidia-smi)
	slots   int

	mu     sync.Mutex
	excl   map[int]string          // device -> owner
	shared map[int]map[string]bool // device -> owners
	owned  map[string][]int
}

func NewGPUs(devices, extra, mounts []string, slots int) *GPUs {
	if slots <= 0 {
		slots = 4
	}
	return &GPUs{Devices: devices, Extra: extra, Mounts: mounts, slots: slots,
		excl: map[int]string{}, shared: map[int]map[string]bool{}, owned: map[string][]int{}}
}

// Allocate gives owner n whole devices, or with shared one slot (n is then
// ignored). It returns the device indices.
func (g *GPUs) Allocate(owner string, n int, shared bool) ([]int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if got := g.owned[owner]; got != nil {
		return got, nil
	}
	var out []int
	if shared {
		best := -1
		for i := range g.Devices {
			if g.excl[i] == "" && len(g.shared[i]) < g.slots && (best < 0 || len(g.shared[i]) < len(g.shared[best])) {
				best = i
			}
		}
		if best < 0 {
			return nil, rpcutil.Err(rpcutil.NoCapacity, "no GPU has a free shared slot")
		}
		out = []int{best}
	} else {
		for i := range g.Devices {
			if len(out) < n && g.excl[i] == "" && len(g.shared[i]) == 0 {
				out = append(out, i)
			}
		}
		if len(out) < n {
			return nil, rpcutil.Err(rpcutil.NoCapacity, "%d free GPU(s), %d requested", len(out), n)
		}
	}
	g.take(owner, out, shared)
	return out, nil
}

func (g *GPUs) take(owner string, idx []int, shared bool) {
	for _, i := range idx {
		if shared {
			if g.shared[i] == nil {
				g.shared[i] = map[string]bool{}
			}
			g.shared[i][owner] = true
		} else {
			g.excl[i] = owner
		}
	}
	g.owned[owner] = idx
}

// Restore records an allocation made before an edge restart.
func (g *GPUs) Restore(owner string, idx []int, shared bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, i := range idx {
		if i < 0 || i >= len(g.Devices) || g.excl[i] != "" || !shared && len(g.shared[i]) > 0 {
			return fmt.Errorf("GPU %d is not available to %s", i, owner)
		}
	}
	g.take(owner, idx, shared)
	return nil
}

func (g *GPUs) Release(owner string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, i := range g.owned[owner] {
		if g.excl[i] == owner {
			delete(g.excl, i)
		}
		delete(g.shared[i], owner)
	}
	delete(g.owned, owner)
}

// Paths returns the device nodes for idx plus the extra ones, sorted.
func (g *GPUs) Paths(idx []int) []string {
	var out []string
	for _, i := range idx {
		out = append(out, g.Devices[i])
	}
	out = append(out, g.Extra...)
	sort.Strings(out)
	return out
}
