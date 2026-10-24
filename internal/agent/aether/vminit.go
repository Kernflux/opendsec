package aether

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/kernflux/opendsec/internal/sandboxfs"
)

// MicroVM guest layout (spec §19.3). The guest boots from the read-only
// agent disk (this binary, chronus, and VMInitName linking to this binary)
// with "init=/opendsec-vminit"; the image, the sandbox's writable disk and its
// config are the next drives. (Init arguments after "--" would not work: the
// VMM appends root= and device parameters at the end of the command line.)
// The config drive is unmounted once read, so a VM restored from a memory
// snapshot can be given a new one.
const (
	VMInitName     = "opendsec-vminit"
	VMImageDevice  = "/dev/vdb" // flattened image, read-only ext4
	VMDiskDevice   = "/dev/vdc" // writable ext4: upper/, work/
	VMConfigDevice = "/dev/vdd" // small ext4 holding VMConfigFile
	VMConfigFile   = "opendsec-vm.json"
	VMVsockPort    = 1024 // aether's Runtime API

	// With the image on virtio-pmem (spec §19.13) the drives after the
	// agent disk move up by one.
	VMImagePmem        = "/dev/pmem0" // the image, mounted with DAX
	VMPmemDiskDevice   = "/dev/vdb"
	VMPmemConfigDevice = "/dev/vdc"
)

// VMConfig is written by the edge into the config disk.
type VMConfig struct {
	Hostname   string   `json:"hostname"`
	AetherArgs []string `json:"aether_args"` // after "--init"
	// Memory optimizations (spec §19.13).
	ZramMB      int64 `json:"zram_mb,omitempty"`      // compressed swap
	ColdAgeS    int   `json:"cold_age_s,omitempty"`   // DAMON_RECLAIM: page out memory idle this long
	ReportOrder int   `json:"report_order,omitempty"` // free page reporting: smallest free block reported (log2 pages); 0 = kernel default
	// Networking (spec §20): eth0's address (CIDR), its gateway and the
	// nameserver.
	// FullInit (fullvm, spec §23): the image's /sbin/init becomes PID 1
	// (e.g. systemd), aether runs as its child.
	FullInit bool `json:"full_init,omitempty"`
	// File access restrictions (spec §21).
	ReadonlyPaths []string `json:"readonly_paths,omitempty"`
	MaskedPaths   []string `json:"masked_paths,omitempty"`
	Address       string   `json:"address,omitempty"`
	Gateway       string   `json:"gateway,omitempty"`
	Nameserver    string   `json:"nameserver,omitempty"`
}

// RunVMInit is PID 1 of a microVM guest: it assembles the sandbox rootfs
// (overlay of the image under the writable disk, agents read-only at
// /.opendsec/bin), pivots into it and execs aether --init, mirroring the
// container backend's sandbox init. It only returns on failure; PID 1
// exiting panics the guest kernel, which ends the VM.
func RunVMInit() int {
	err := vmInit()
	fmt.Fprintln(os.Stderr, "opendsec vm init:", err)
	return 1
}

func vmInit() error {
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount /proc: %w", err)
	}
	image, imageOpts, disk, config := VMImageDevice, "", VMDiskDevice, VMConfigDevice
	if _, err := os.Stat(VMImagePmem); err == nil {
		// DAX: image files are read (and mapped) straight from the host's
		// page cache, shared by the VMs of the image, not cached again here.
		image, imageOpts, disk, config = VMImagePmem, "dax", VMPmemDiskDevice, VMPmemConfigDevice
	}
	fstype := imageFS(image)
	if fstype == "erofs" && imageOpts == "dax" {
		imageOpts = "dax=always"
	}
	if err := unix.Mount(image, "/lower", fstype, unix.MS_RDONLY, imageOpts); err != nil {
		return fmt.Errorf("mount image %s: %w", image, err)
	}
	// The disk is a fresh sparse file: its uninitialized inode tables read
	// as zeros, so skip the background zeroing that would allocate them.
	if err := unix.Mount(disk, "/rw", "ext4", unix.MS_NOATIME, "noinit_itable"); err != nil {
		return fmt.Errorf("mount disk %s: %w", disk, err)
	}
	if err := unix.Mount(config, "/cfg", "ext4", unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("mount config %s: %w", config, err)
	}
	var cfg VMConfig
	b, err := os.ReadFile(filepath.Join("/cfg", VMConfigFile))
	unix.Unmount("/cfg", 0)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("%s: %w", VMConfigFile, err)
	}
	const root = "/newroot"
	if err := unix.Mount("overlay", root, "overlay", 0, "lowerdir=/lower,upperdir=/rw/upper,workdir=/rw/work"); err != nil {
		return fmt.Errorf("mount overlay: %w", err)
	}
	r := func(p string) string { return filepath.Join(root, p) }
	for _, d := range []string{".opendsec/bin", ".opendsec/run", "proc", "sys", "dev", "tmp"} {
		if err := os.MkdirAll(r(d), 0o755); err != nil {
			return err
		}
	}
	os.Chmod(r("tmp"), 0o1777)
	// The agent disk is our root: bind it read-only at /.opendsec/bin.
	if err := unix.Mount("/", r(".opendsec/bin"), "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind agents: %w", err)
	}
	unix.Mount("", r(".opendsec/bin"), "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, "")
	if err := unix.Mount("sysfs", r("sys"), "sysfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount sysfs: %w", err)
	}
	err = setupMemory(r("sys"), &cfg)
	unix.Unmount(r("sys"), 0)
	if err != nil {
		return fmt.Errorf("memory setup: %w", err)
	}
	mounts := []struct {
		src, dst, fstype string
		flags            uintptr
		data             string
	}{
		{"tmpfs", ".opendsec/run", "tmpfs", unix.MS_NOSUID | unix.MS_NODEV, "mode=711"}, // init_user traverses it
		{"proc", "proc", "proc", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"sysfs", "sys", "sysfs", unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"cgroup2", "sys/fs/cgroup", "cgroup2", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"devtmpfs", "dev", "devtmpfs", unix.MS_NOSUID, "mode=755"},
	}
	for _, m := range mounts {
		if err := unix.Mount(m.src, r(m.dst), m.fstype, m.flags, m.data); err != nil {
			return fmt.Errorf("mount %s: %w", m.dst, err)
		}
	}
	for _, d := range []string{"dev/pts", "dev/shm"} {
		os.MkdirAll(r(d), 0o755)
	}
	if cfg.Nameserver != "" {
		f := r(".opendsec/run/resolv.conf")
		if err := os.WriteFile(f, []byte("nameserver "+cfg.Nameserver+"\noptions timeout:2 attempts:2\n"), 0o644); err != nil {
			return err
		}
		if err := bindResolv(f, root); err != nil {
			return fmt.Errorf("resolv.conf: %w", err)
		}
	}
	if err := unix.Mount("devpts", r("dev/pts"), "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620"); err != nil {
		return fmt.Errorf("devpts: %w", err)
	}
	if err := unix.Mount("shm", r("dev/shm"), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777"); err != nil {
		return err
	}
	os.Remove(r("dev/ptmx"))
	for name, target := range map[string]string{"ptmx": "pts/ptmx", "fd": "/proc/self/fd", "stdin": "/proc/self/fd/0",
		"stdout": "/proc/self/fd/1", "stderr": "/proc/self/fd/2"} {
		os.Symlink(target, r("dev/"+name))
	}
	if err := unix.Chdir(root); err != nil {
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
	if err := sandboxfs.Apply(cfg.ReadonlyPaths, cfg.MaskedPaths); err != nil {
		return err
	}
	if err := linkUp("lo"); err != nil {
		return fmt.Errorf("lo up: %w", err)
	}
	if cfg.Address != "" {
		if err := configureNIC("eth0", cfg.Address, cfg.Gateway); err != nil {
			return fmt.Errorf("eth0: %w", err)
		}
	}
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"}
	if cfg.FullInit {
		if _, err := os.Stat("/sbin/init"); err == nil {
			srv := exec.Command("/.opendsec/bin/opendsec-aether", cfg.AetherArgs...)
			srv.Env, srv.Stdout, srv.Stderr = env, os.Stderr, os.Stderr
			srv.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if err := srv.Start(); err != nil {
				return fmt.Errorf("start aether: %w", err)
			}
			protectFromOOM(srv.Process.Pid)
			return unix.Exec("/sbin/init", []string{"/sbin/init"}, env)
		}
	}
	protectFromOOM(os.Getpid())
	argv := append([]string{"/.opendsec/bin/opendsec-aether", "--init"}, cfg.AetherArgs...)
	return unix.Exec(argv[0], argv, env)
}

// linkUp sets IFF_UP on interface name.
func linkUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var ifr [unix.IFNAMSIZ + 24]byte
	copy(ifr[:], name)
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

// bindResolv binds file read-only at <root>/etc/resolv.conf (when the image
// has an /etc), replacing a symlink there.
func bindResolv(file, root string) error {
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
	if err := unix.Mount(file, dst, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	return unix.Mount("", dst, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, "")
}

// configureNIC gives interface name the address cidr, brings it up and
// routes everything through gw (ioctls: no tools in the guest).
func configureNIC(name, cidr, gw string) error {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	gwIP := net.ParseIP(gw).To4()
	if ip.To4() == nil || gwIP == nil {
		return fmt.Errorf("bad address %s / gateway %s", cidr, gw)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifreq := func(addr net.IP) []byte {
		b := make([]byte, unix.IFNAMSIZ+24)
		copy(b, name)
		putSockaddr(b[unix.IFNAMSIZ:], addr)
		return b
	}
	for _, op := range []struct {
		req  uintptr
		addr net.IP
	}{{unix.SIOCSIFADDR, ip.To4()}, {unix.SIOCSIFNETMASK, net.IP(n.Mask).To4()}} {
		b := ifreq(op.addr)
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), op.req, uintptr(unsafe.Pointer(&b[0]))); e != 0 {
			return e
		}
	}
	if err := linkUp(name); err != nil {
		return err
	}
	// struct rtentry (x86_64): pad, dst, gateway, genmask, flags, ...
	var rt [120]byte
	putSockaddr(rt[8:], net.IPv4zero.To4())
	putSockaddr(rt[24:], gwIP)
	putSockaddr(rt[40:], net.IPv4zero.To4())
	binary.LittleEndian.PutUint16(rt[56:], unix.RTF_UP|unix.RTF_GATEWAY)
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), unix.SIOCADDRT, uintptr(unsafe.Pointer(&rt[0]))); e != 0 {
		return fmt.Errorf("default route: %w", e)
	}
	return nil
}

// putSockaddr writes a struct sockaddr_in for ip.
func putSockaddr(b []byte, ip net.IP) {
	binary.LittleEndian.PutUint16(b, unix.AF_INET)
	copy(b[4:8], ip)
}

// protectFromOOM makes the guest's OOM killer spare pid (aether; inherited
// by chronus, which puts the commands it starts back at 0).
func protectFromOOM(pid int) {
	os.WriteFile(fmt.Sprintf("/proc/%d/oom_score_adj", pid), []byte("-1000"), 0)
}

// imageFS tells the image disk's filesystem: EROFS (built once in the
// store, spec §29.4) by its superblock magic, else ext4.
func imageFS(dev string) string {
	f, err := os.Open(dev)
	if err != nil {
		return "ext4"
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.ReadAt(magic[:], 1024); err == nil && magic == [4]byte{0xe2, 0xe1, 0xf5, 0xe0} {
		return "erofs"
	}
	return "ext4"
}
