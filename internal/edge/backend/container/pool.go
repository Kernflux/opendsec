package container

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/edge/backend"
	"github.com/kernflux/opendsec/internal/edge/backend/linuxrt"
	"github.com/kernflux/opendsec/internal/ids"
)

// warmPool keeps sandboxes of some images started ahead of requests (the
// FnCall backend, spec §22.3: a function call should not wait for a
// sandbox to boot). A request it can serve takes a member: its limits,
// network and id are set then. Members keep their own lease internally
// (state dir, cgroup); the sandbox's lease is a symlink to it in the state
// dir, followed by Adopt and CleanupExcept.
type warmPool struct {
	b     *Backend
	sizes map[string]int // image -> members kept ready

	mu    sync.Mutex
	ready map[string][]*sandbox
	own   map[string]bool // leases of members, starting or waiting
	kick  chan struct{}
	done  chan struct{}
	once  sync.Once
	wg    sync.WaitGroup
}

func newWarmPool(b *Backend, sizes map[string]int) *warmPool {
	p := &warmPool{b: b, sizes: sizes, ready: map[string][]*sandbox{}, own: map[string]bool{}, kick: make(chan struct{}, 1), done: make(chan struct{})}
	p.wg.Add(1)
	go p.fill()
	return p
}

// eligible: a request a warm member can serve unchanged but for its limits
// and network.
func (p *warmPool) eligible(spec *pb.SandboxSpec) bool {
	return p.sizes[spec.Image] > 0 && spec.Snapshot == "" && spec.InitUser == "" && spec.Labels["workdir"] == "" &&
		len(spec.ReadonlyPaths) == 0 && len(spec.MaskedPaths) == 0 && spec.Resources.GetGpus() == 0 && spec.GpuMode == "" &&
		(spec.Resources.GetDiskMb() == 0 || spec.Resources.GetDiskMb() == p.b.opt.DefaultDiskMB)
}

// take returns a live member for sb, or nil.
func (p *warmPool) take(sb *backend.Sandbox) *sandbox {
	if p == nil || !p.eligible(sb.Spec) {
		return nil
	}
	defer p.refill()
	p.mu.Lock()
	defer p.mu.Unlock()
	for q := p.ready[sb.Spec.Image]; len(q) > 0; q = p.ready[sb.Spec.Image] {
		s := q[0]
		p.ready[sb.Spec.Image] = q[1:]
		delete(p.own, s.lease)
		select {
		case <-s.exited:
			go p.b.teardown(s)
		default:
			return s
		}
	}
	return nil
}

func (p *warmPool) refill() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

func (p *warmPool) fill() {
	defer p.wg.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		for img, n := range p.sizes {
			for {
				p.mu.Lock()
				have := len(p.ready[img])
				p.mu.Unlock()
				if have >= n {
					break
				}
				select {
				case <-p.done:
					return
				default:
				}
				s, err := p.start(img)
				if err != nil {
					p.b.opt.Log.Warn("warm pool: start", "image", img, "err", err)
					break
				}
				p.mu.Lock()
				p.ready[img] = append(p.ready[img], s)
				p.mu.Unlock()
			}
		}
		select {
		case <-p.done:
			return
		case <-p.kick:
		case <-t.C:
		}
	}
}

func (p *warmPool) start(img string) (*sandbox, error) {
	lease := ids.NewLease()
	p.mu.Lock()
	p.own[lease] = true
	p.mu.Unlock()
	spec := &pb.SandboxSpec{Image: img, Resources: &pb.Resources{DiskMb: p.b.opt.DefaultDiskMB}}
	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()
	s, err := p.b.start(ctx, &backend.Sandbox{ID: ids.Sandbox(p.b.opt.EdgeID, lease), Spec: spec}, lease, true)
	if err != nil {
		p.mu.Lock()
		delete(p.own, lease)
		p.mu.Unlock()
	}
	return s, err
}

// owns reports whether lease is a member's (CleanupExcept spares it).
func (p *warmPool) owns(lease string) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.own[lease]
}

// close stops filling and tears the waiting members down.
func (p *warmPool) close() {
	if p == nil {
		return
	}
	p.once.Do(func() { close(p.done) })
	p.wg.Wait()
	p.mu.Lock()
	var all []*sandbox
	for _, q := range p.ready {
		all = append(all, q...)
	}
	p.ready, p.own = map[string][]*sandbox{}, map[string]bool{}
	p.mu.Unlock()
	for _, s := range all {
		p.b.teardown(s)
	}
}

// assign turns warm member s into sandbox sb (lease).
func (b *Backend) assign(s *sandbox, sb *backend.Sandbox, lease string) error {
	spec := sb.Spec
	fail := func(err error) error {
		b.teardown(s)
		return err
	}
	if err := s.cg.SetLimits(linuxrt.Limits{CPUCores: spec.Resources.GetCpuCores(), MemoryMB: spec.Resources.GetMemoryMb(),
		BestEffort: spec.Qos == "BE"}); err != nil {
		return fail(err)
	}
	if sb.Net != nil {
		if err := sb.Net.Setup(s.pid, 0); err != nil {
			return fail(err)
		}
		if err := writeInPlace(filepath.Join(s.dir, "resolv.conf"), resolvConf(sb.Net)); err != nil {
			return fail(err)
		}
	}
	if err := os.Symlink(s.lease, filepath.Join(b.sbRoot(), lease)); err != nil {
		return fail(err)
	}
	s.mu.Lock()
	s.id, s.alias = sb.ID, lease
	s.mu.Unlock()
	b.mu.Lock()
	b.sbs[sb.ID] = s
	b.mu.Unlock()
	return nil
}

// writeInPlace rewrites a file keeping its inode (it is bind-mounted).
func writeInPlace(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
