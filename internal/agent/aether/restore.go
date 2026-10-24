package aether

import (
	"context"
	"encoding/binary"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
)

// PostRestore gives a guest resumed from a memory snapshot its own clock,
// randomness and identity (spec §19.3). Processes keep running; the kernel
// already dropped vsock connections, and the edge redials.
func (a *Aether) PostRestore(_ context.Context, r *pb.PostRestoreRequest) (*pb.Empty, error) {
	if r.UnixNanos > 0 {
		tv := unix.NsecToTimeval(r.UnixNanos)
		if err := unix.Settimeofday(&tv); err != nil {
			return nil, status.Errorf(codes.Internal, "set clock: %v", err)
		}
	}
	if len(r.Entropy) > 0 {
		if err := addEntropy(r.Entropy); err != nil {
			return nil, status.Errorf(codes.Internal, "entropy: %v", err)
		}
	}
	if r.Hostname != "" {
		if err := unix.Sethostname([]byte(r.Hostname)); err != nil {
			return nil, status.Errorf(codes.Internal, "hostname: %v", err)
		}
	}
	if r.MachineId != "" {
		if _, err := os.Stat("/etc/machine-id"); err == nil {
			if err := os.WriteFile("/etc/machine-id", []byte(r.MachineId+"\n"), 0o444); err != nil {
				return nil, status.Errorf(codes.Internal, "machine-id: %v", err)
			}
		}
	}
	return &pb.Empty{}, nil
}

// addEntropy mixes b into the kernel pool, credited (RNDADDENTROPY), and
// reseeds the CRNG so every copy's /dev/urandom diverges immediately.
func addEntropy(b []byte) error {
	f, err := os.OpenFile("/dev/urandom", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	// struct rand_pool_info { int entropy_count; int buf_size; __u32 buf[]; }
	info := make([]byte, 8+len(b))
	binary.NativeEndian.PutUint32(info[0:], uint32(len(b)*8))
	binary.NativeEndian.PutUint32(info[4:], uint32(len(b)))
	copy(info[8:], b)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.RNDADDENTROPY, uintptr(unsafe.Pointer(&info[0]))); e != 0 {
		return e
	}
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.RNDRESEEDCRNG, 0); e != 0 {
		return e
	}
	return nil
}
