package aether

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

// setupMemory applies the guest memory optimizations of cfg (spec §19.13),
// with sysfs mounted at sys: zram swap, DAMON_RECLAIM paging out cold
// memory to it, and the free page reporting granularity (the pages freed
// go back to the host through the balloon device).
func setupMemory(sys string, cfg *VMConfig) error {
	if cfg.ZramMB > 0 {
		if err := writeSys(sys, "block/zram0/disksize", strconv.FormatInt(cfg.ZramMB<<20, 10)); err != nil {
			return err
		}
		if err := mkswap("/dev/zram0", cfg.ZramMB<<20); err != nil {
			return err
		}
		if err := swapon("/dev/zram0"); err != nil {
			return fmt.Errorf("swapon zram: %w", err)
		}
	}
	if cfg.ReportOrder > 0 {
		if err := writeSys(sys, "module/page_reporting/parameters/page_reporting_order", strconv.Itoa(cfg.ReportOrder)); err != nil {
			return err
		}
	}
	if cfg.ColdAgeS > 0 {
		p := "module/damon_reclaim/parameters/"
		// Always active: the watermarks (free memory, per mille) would
		// otherwise keep it off while the guest has free memory, but cold
		// memory costs the host whether or not the guest is short of it.
		for _, kv := range [][2]string{
			{"min_age", strconv.FormatInt(int64(cfg.ColdAgeS)*1e6, 10)},
			{"wmarks_high", "1000"}, {"wmarks_mid", "1000"}, {"wmarks_low", "0"},
			{"enabled", "Y"},
		} {
			if err := writeSys(sys, p+kv[0], kv[1]); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeSys(sys, p, v string) error {
	if err := os.WriteFile(filepath.Join(sys, p), []byte(v), 0); err != nil {
		return fmt.Errorf("set %s: %w", p, err)
	}
	return nil
}

// mkswap writes a swap signature (version 1, no bad pages) on dev.
func mkswap(dev string, size int64) error {
	ps := int64(os.Getpagesize())
	hdr := make([]byte, ps)
	binary.LittleEndian.PutUint32(hdr[1024:], 1)                 // version
	binary.LittleEndian.PutUint32(hdr[1028:], uint32(size/ps-1)) // last_page
	copy(hdr[ps-10:], "SWAPSPACE2")
	f, err := os.OpenFile(dev, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(hdr, 0); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func swapon(dev string) error {
	p, err := unix.BytePtrFromString(dev)
	if err != nil {
		return err
	}
	if _, _, e := unix.Syscall(unix.SYS_SWAPON, uintptr(unsafe.Pointer(p)), 0, 0); e != 0 {
		return e
	}
	return nil
}
