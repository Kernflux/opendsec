package container

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/kernflux/opendsec/internal/edge/backend/linuxrt"
	"github.com/kernflux/opendsec/internal/sandboxfs"
)

// initArg0 is argv[0] of the re-executed edge binary that becomes the
// sandbox's setup process (the docker/runc "reexec" pattern). Any binary that
// links this package (opendsec-edge, opendsecctl, tests) can act as it.
const (
	initArg0   = "opendsec-sandbox-init"
	initEnvKey = "OPENDSEC_SANDBOX_INIT"
)

// initConfig is passed from the edge to the setup process.
type initConfig struct {
	Lower      []string `json:"lower"`     // overlay lowerdirs, topmost first
	Disk       string   `json:"disk"`      // loop device of the writable disk (upper/, work/)
	DiskDir    string   `json:"disk_dir"`  // where to mount it (in the sandbox's mount namespace)
	Rootfs     string   `json:"rootfs"`    // mountpoint for the merged rootfs
	AgentDir   string   `json:"agent_dir"` // host dir with opendsec-aether, opendsec-chronus
	RunDir     string   `json:"run_dir"`   // host dir mounted at /.opendsec/run
	Hostname   string   `json:"hostname"`
	AetherArgs []string `json:"aether_args"`
	Resolv     string   `json:"resolv,omitempty"` // host file bound at /etc/resolv.conf (networking, spec §20)
	// File access restrictions (spec §21), applied with the /proc defaults.
	ReadonlyPaths []string `json:"readonly_paths,omitempty"`
	MaskedPaths   []string `json:"masked_paths,omitempty"`
	// GPUs (spec §22.2): device nodes bound under /dev, host paths bound
	// read-only at the same place.
	Devices []string `json:"devices,omitempty"`
	Mounts  []string `json:"mounts,omitempty"`
	// CoreSched: take a new core scheduling cookie first, before anything
	// here starts a process: all of the sandbox inherits it (spec §29.1).
	CoreSched bool `json:"core_sched,omitempty"`
}

func init() {
	if len(os.Args) > 0 && os.Args[0] == initArg0 {
		if err := sandboxInit(); err != nil {
			fmt.Fprintln(os.Stderr, "opendsec-sandbox-init:", err)
			os.Exit(1)
		}
		panic("unreachable: exec returned")
	}
}

// sandboxInit runs in fresh mount/pid/uts/ipc/net/cgroup namespaces, inside
// the sandbox's cgroup. It assembles the rootfs, pivots into it, and execs
// aether as PID 1.
func sandboxInit() error {
	// Capabilities are per thread: drop them on the thread that execs.
	runtime.LockOSThread()
	var cfg initConfig
	if err := json.Unmarshal([]byte(os.Getenv(initEnvKey)), &cfg); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if cfg.CoreSched {
		if err := linuxrt.CoreSchedNew(0); err != nil {
			return err
		}
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make / private: %w", err)
	}
	if err := unix.Mount(cfg.Disk, cfg.DiskDir, "ext4", unix.MS_NOATIME, ""); err != nil {
		return fmt.Errorf("mount writable disk %s: %w", cfg.Disk, err)
	}
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", strings.Join(cfg.Lower, ":"),
		filepath.Join(cfg.DiskDir, "upper"), filepath.Join(cfg.DiskDir, "work"))
	if err := unix.Mount("overlay", cfg.Rootfs, "overlay", 0, opts); err != nil {
		return fmt.Errorf("mount overlay (%s): %w", opts, err)
	}
	r := func(p string) string { return filepath.Join(cfg.Rootfs, p) }

	for _, d := range []string{".opendsec/bin", ".opendsec/run", ".opendsec/disk", "proc", "sys", "dev", "tmp"} {
		if err := os.MkdirAll(r(d), 0o755); err != nil {
			return err
		}
	}
	os.Chmod(r("tmp"), 0o1777)
	if err := bind(cfg.AgentDir, r(".opendsec/bin"), true); err != nil {
		return fmt.Errorf("agent dir: %w", err)
	}
	if err := bind(cfg.RunDir, r(".opendsec/run"), false); err != nil {
		return fmt.Errorf("run dir: %w", err)
	}
	// The edge reaches the writable layer here (pack_diff, snapshots).
	if err := bind(cfg.DiskDir, r(".opendsec/disk"), false); err != nil {
		return fmt.Errorf("disk dir: %w", err)
	}
	os.Chmod(r(".opendsec/disk"), 0o700)
	if err := unix.Mount("proc", r("proc"), "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount proc: %w", err)
	}
	if err := unix.Mount("sysfs", r("sys"), "sysfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount sysfs: %w", err)
	}
	// The sandbox's own cgroup (its root, through the cgroup namespace), so
	// runtimes inside (Go, the JVM) size themselves to its limits.
	if err := unix.Mount("cgroup2", r("sys/fs/cgroup"), "cgroup2", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount cgroup2: %w", err)
	}
	if err := setupDev(r("dev")); err != nil {
		return fmt.Errorf("/dev: %w", err)
	}
	for _, d := range cfg.Devices {
		p := r(filepath.Join("dev", filepath.Base(d)))
		if err := os.WriteFile(p, nil, 0o666); err != nil {
			return err
		}
		if err := unix.Mount(d, p, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("device %s: %w", d, err)
		}
	}
	for _, m := range cfg.Mounts {
		fi, err := os.Stat(m)
		if err != nil {
			return fmt.Errorf("gpu mount %s: %w", m, err)
		}
		p := r(m)
		if fi.IsDir() {
			err = os.MkdirAll(p, 0o755)
		} else if err = os.MkdirAll(filepath.Dir(p), 0o755); err == nil {
			if _, serr := os.Stat(p); serr != nil {
				err = os.WriteFile(p, nil, 0o644)
			}
		}
		if err != nil {
			return err
		}
		if err := bind(m, p, true); err != nil {
			return fmt.Errorf("gpu mount %s: %w", m, err)
		}
	}
	if cfg.Resolv != "" {
		if err := BindResolv(cfg.Resolv, cfg.Rootfs); err != nil {
			return fmt.Errorf("resolv.conf: %w", err)
		}
	}

	// pivot_root(".", ".") stacks the old root on top of the new one; a lazy
	// unmount then drops it, leaving only the sandbox rootfs.
	if err := unix.Chdir(cfg.Rootfs); err != nil {
		return err
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	unix.Sethostname([]byte(cfg.Hostname))
	if err := loopbackUp(); err != nil {
		return fmt.Errorf("lo up: %w", err)
	}
	if err := sandboxfs.Apply(append(sandboxfs.ProcReadonly, cfg.ReadonlyPaths...),
		append(sandboxfs.ProcMasked, cfg.MaskedPaths...)); err != nil {
		return err
	}
	// The OOM killer spares the agents (chronus puts what it starts back
	// at 0): a sandbox at its memory limit loses a process, not its API.
	// Lowering it needs CAP_SYS_RESOURCE, about to go.
	os.WriteFile("/proc/self/oom_score_adj", []byte("-1000"), 0)
	// Last: the filter refuses mounts, the capabilities go.
	if err := installSeccomp(); err != nil {
		return err
	}
	if err := dropCaps(); err != nil {
		return err
	}
	os.Unsetenv(initEnvKey)
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"}
	argv := append([]string{"/.opendsec/bin/opendsec-aether", "--init"}, cfg.AetherArgs...)
	return unix.Exec(argv[0], argv, env)
}

func bind(src, dst string, ro bool) error {
	if err := unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}
	if ro {
		return unix.Mount("", dst, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, "")
	}
	return nil
}

// setupDev mounts a minimal /dev: a tmpfs with the standard character
// devices bind-mounted from the host, a private devpts and /dev/shm.
func setupDev(dev string) error {
	if err := unix.Mount("tmpfs", dev, "tmpfs", unix.MS_NOSUID|unix.MS_STRICTATIME, "mode=755,size=65536k"); err != nil {
		return err
	}
	for _, d := range []string{"null", "zero", "full", "random", "urandom", "tty"} {
		p := filepath.Join(dev, d)
		f, err := os.Create(p)
		if err != nil {
			return err
		}
		f.Close()
		if err := unix.Mount("/dev/"+d, p, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind /dev/%s: %w", d, err)
		}
	}
	for _, d := range []string{"pts", "shm"} {
		if err := os.Mkdir(filepath.Join(dev, d), 0o755); err != nil {
			return err
		}
	}
	if err := unix.Mount("devpts", filepath.Join(dev, "pts"), "devpts", unix.MS_NOSUID|unix.MS_NOEXEC,
		"newinstance,ptmxmode=0666,mode=0620"); err != nil {
		return fmt.Errorf("devpts: %w", err)
	}
	if err := unix.Mount("shm", filepath.Join(dev, "shm"), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777,size=65536k"); err != nil {
		return err
	}
	links := map[string]string{"ptmx": "pts/ptmx", "fd": "/proc/self/fd", "stdin": "/proc/self/fd/0",
		"stdout": "/proc/self/fd/1", "stderr": "/proc/self/fd/2"}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(dev, name)); err != nil {
			return err
		}
	}
	return nil
}

// loopbackUp sets IFF_UP on "lo" in the sandbox's (otherwise empty) netns.
func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var ifr [unix.IFNAMSIZ + 24]byte
	copy(ifr[:], "lo")
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return e
	}
	flags := (*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ]))
	*flags |= unix.IFF_UP | unix.IFF_RUNNING
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return e
	}
	return nil
}

// BindResolv binds file read-only at <root>/etc/resolv.conf (when the image
// has an /etc), replacing a symlink there (e.g. to systemd-resolved's stub).
func BindResolv(file, root string) error {
	etc := filepath.Join(root, "etc")
	if fi, err := os.Stat(etc); err != nil || !fi.IsDir() {
		return nil
	}
	dst := filepath.Join(etc, "resolv.conf")
	if fi, err := os.Lstat(dst); err != nil || !fi.Mode().IsRegular() {
		os.RemoveAll(dst)
		if err := os.WriteFile(dst, nil, 0o644); err != nil {
			return err
		}
	}
	return bind(file, dst, true)
}
