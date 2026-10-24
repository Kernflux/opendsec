package aether

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// ListenVsock serves on AF_VSOCK port (microvm backends, spec §19.3): the
// edge reaches it through Firecracker's vsock Unix socket. The net package
// has no vsock support, so the listener and its connections are pollable
// os.Files (deadlines and Close-unblocks-Accept work as for sockets).
func ListenVsock(port uint32) (net.Listener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock bind %d: %w", port, err)
	}
	if err := unix.Listen(fd, 128); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock listen: %w", err)
	}
	return &vsockListener{f: os.NewFile(uintptr(fd), "vsock"), addr: vsockAddr(fmt.Sprintf("vsock:%d", port))}, nil
}

type vsockAddr string

func (a vsockAddr) Network() string { return "vsock" }
func (a vsockAddr) String() string  { return string(a) }

type vsockListener struct {
	f    *os.File
	addr vsockAddr
}

func (l *vsockListener) Accept() (net.Conn, error) {
	rc, err := l.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var nfd int
	var aerr error
	if err := rc.Read(func(fd uintptr) bool {
		nfd, _, aerr = unix.Accept4(int(fd), unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
		return aerr != unix.EAGAIN
	}); err != nil {
		return nil, err
	}
	if aerr != nil {
		return nil, aerr
	}
	return &vsockConn{File: os.NewFile(uintptr(nfd), "vsock-conn"), local: l.addr}, nil
}

func (l *vsockListener) Close() error   { return l.f.Close() }
func (l *vsockListener) Addr() net.Addr { return l.addr }

// vsockConn is an accepted connection; *os.File supplies Read, Write, Close
// and the deadlines.
type vsockConn struct {
	*os.File
	local vsockAddr
}

func (c *vsockConn) LocalAddr() net.Addr  { return c.local }
func (c *vsockConn) RemoteAddr() net.Addr { return vsockAddr("vsock:host") }

// DialVsock connects to port on the VM with context id cid (vhost-vsock,
// the fullvm backend, spec §23), as a pollable os.File like the listener's.
func DialVsock(cid, port uint32, timeout time.Duration) (net.Conn, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	f := os.NewFile(uintptr(fd), "vsock-conn")
	err = unix.Connect(fd, &unix.SockaddrVM{CID: cid, Port: port})
	if err == unix.EINPROGRESS {
		f.SetWriteDeadline(time.Now().Add(timeout))
		rc, rerr := f.SyscallConn()
		if rerr != nil {
			f.Close()
			return nil, rerr
		}
		first := true
		werr := rc.Write(func(fd uintptr) bool {
			if first { // wait until writable: the connection is then done
				first = false
				return false
			}
			v, gerr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ERROR)
			if gerr != nil {
				err = gerr
				return true
			}
			if v == int(unix.EINPROGRESS) || v == int(unix.EAGAIN) {
				return false
			}
			err = nil
			if v != 0 {
				err = unix.Errno(v)
			}
			return true
		})
		if werr != nil {
			err = werr
		}
		f.SetWriteDeadline(time.Time{})
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return &vsockConn{File: f, local: vsockAddr("vsock:host")}, nil
}
