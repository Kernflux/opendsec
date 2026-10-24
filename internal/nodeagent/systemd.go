package nodeagent

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Systemd is what the agent needs from systemd; tests use a fake.
type Systemd interface {
	DaemonReload(ctx context.Context) error
	// Run performs one of start|stop|restart|enable|disable on unit.
	Run(ctx context.Context, verb, unit string) error
	ActiveState(ctx context.Context, unit string) string
	// RestartSelf restarts the agent's own unit without waiting for it.
	RestartSelf(ctx context.Context) error
}

// Systemctl drives the real systemd.
type Systemctl struct {
	Bin  string // default "systemctl"
	Self string // the agent's unit, default opendsec-nodeagent.service
}

func (s Systemctl) bin() string {
	if s.Bin == "" {
		return "systemctl"
	}
	return s.Bin
}

func (s Systemctl) run(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, s.bin(), args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func (s Systemctl) DaemonReload(ctx context.Context) error {
	_, err := s.run(ctx, "daemon-reload")
	return err
}

func (s Systemctl) Run(ctx context.Context, verb, unit string) error {
	switch verb {
	case "start", "stop", "restart", "enable", "disable":
	default:
		return fmt.Errorf("systemctl verb %q not allowed", verb)
	}
	if !allowedUnit(unit) {
		return fmt.Errorf("unit %q is not an OpenDsec unit", unit)
	}
	_, err := s.run(ctx, verb, unit)
	return err
}

func (s Systemctl) ActiveState(ctx context.Context, unit string) string {
	out, err := s.run(ctx, "show", "-p", "ActiveState", "--value", unit)
	if err != nil {
		return "unknown"
	}
	return out
}

func (s Systemctl) RestartSelf(ctx context.Context) error {
	self := s.Self
	if self == "" {
		self = "opendsec-nodeagent.service"
	}
	_, err := s.run(ctx, "restart", "--no-block", self)
	return err
}

// allowedUnit: the agent only ever touches OpenDsec's own units (spec §28.4).
func allowedUnit(u string) bool {
	if !strings.HasPrefix(u, "opendsec-") || !strings.HasSuffix(u, ".service") {
		return false
	}
	return strings.Trim(u, "abcdefghijklmnopqrstuvwxyz0123456789-@.") == ""
}
