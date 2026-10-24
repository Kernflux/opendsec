package container

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

// makeDisk creates the sandbox's writable layer (spec §11.2): a sparse
// ext4 image of sizeMB at img, holding upper/ and work/, attached to an
// auto-clearing loop device. The sandbox's init mounts it in its own mount
// namespace (a mount on the host would make every new mount namespace
// copy one more mount: at thousands of sandboxes each start slowed by
// ~0.1 s); the device is freed with the last unmount. The caller keeps the
// returned file open until then, else the device is cleared at once.
func makeDisk(img string, sizeMB int64) (dev string, rdev uint64, keep *os.File, err error) {
	stage, err := os.MkdirTemp(filepath.Dir(img), "disk-stage-")
	if err != nil {
		return "", 0, nil, err
	}
	defer os.RemoveAll(stage)
	for _, d := range []string{"upper", "work"} {
		if err := os.Mkdir(filepath.Join(stage, d), 0o755); err != nil {
			return "", 0, nil, err
		}
	}
	f, err := os.OpenFile(img, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", 0, nil, err
	}
	if err := f.Truncate(sizeMB << 20); err != nil {
		f.Close()
		return "", 0, nil, err
	}
	f.Close()
	out, err := exec.Command("mkfs.ext4", "-q", "-F", "-O", "^has_journal",
		"-E", "lazy_itable_init=1,root_owner=0:0", "-m", "0", "-d", stage, img).CombinedOutput()
	if err != nil {
		return "", 0, nil, fmt.Errorf("mkfs.ext4: %v: %s", err, out)
	}
	return attachLoop(img)
}

// loopMu serializes taking a loop device: concurrent creations would be
// handed the same free one (LOOP_CTL_GET_FREE) and all but one retry,
// which under a burst of hundreds runs out of attempts.
var loopMu sync.Mutex

func attachLoop(img string) (string, uint64, *os.File, error) {
	imgf, err := os.OpenFile(img, os.O_RDWR, 0)
	if err != nil {
		return "", 0, nil, err
	}
	defer imgf.Close()
	ctl, err := os.OpenFile("/dev/loop-control", os.O_RDWR, 0)
	if err != nil {
		return "", 0, nil, err
	}
	defer ctl.Close()
	loopMu.Lock()
	defer loopMu.Unlock()
	for attempt := 0; attempt < 32; attempt++ {
		n, err := unix.IoctlRetInt(int(ctl.Fd()), unix.LOOP_CTL_GET_FREE)
		if err != nil {
			return "", 0, nil, fmt.Errorf("loop-control: %w", err)
		}
		dev := fmt.Sprintf("/dev/loop%d", n)
		lf, err := os.OpenFile(dev, os.O_RDWR, 0)
		if err != nil {
			return "", 0, nil, err
		}
		cfg := unix.LoopConfig{Fd: uint32(imgf.Fd())}
		cfg.Info.Flags = unix.LO_FLAGS_AUTOCLEAR
		err = unix.IoctlLoopConfigure(int(lf.Fd()), &cfg)
		if errors.Is(err, unix.EBUSY) {
			lf.Close() // taken by another process meanwhile
			continue
		}
		if err != nil {
			lf.Close()
			return "", 0, nil, fmt.Errorf("configure %s: %w", dev, err)
		}
		var st unix.Stat_t
		if err := unix.Fstat(int(lf.Fd()), &st); err != nil {
			lf.Close()
			return "", 0, nil, err
		}
		return dev, st.Rdev, lf, nil
	}
	return "", 0, nil, fmt.Errorf("no free loop device")
}

func unmount(dir string) {
	if err := unix.Unmount(dir, 0); err != nil && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOENT) {
		unix.Unmount(dir, unix.MNT_DETACH)
	}
}

func haveMkfs() bool {
	_, err := exec.LookPath("mkfs.ext4")
	return err == nil
}
