package backend

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// sunPath is the size of sockaddr_un.sun_path on Linux, NUL included.
const sunPath = 108

// DialUnix dials the unix socket at path. A sandbox's sockets sit under the
// edge's state directory, which holds the edge's name (the host name on a
// quickstart node, up to 63 characters on a cloud machine), so their paths
// can be longer than sun_path, and connect fails with EINVAL. Such a path is
// reached through /proc/self/fd of its directory instead.
func DialUnix(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	if len(path) < sunPath {
		return d.DialContext(ctx, "unix", path)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer dir.Close() // connect resolved the path: the socket stays connected
	return d.DialContext(ctx, "unix", fmt.Sprintf("/proc/self/fd/%d/%s", dir.Fd(), filepath.Base(path)))
}
