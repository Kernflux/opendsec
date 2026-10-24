package peerfile

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
)

// pipe returns a send func and the matching recv func.
func pipe() (func(*pb.SnapshotChunk) error, func() (*pb.SnapshotChunk, error), func()) {
	ch := make(chan *pb.SnapshotChunk, 1024)
	send := func(c *pb.SnapshotChunk) error {
		// Send reuses its buffer: copy as a real stream would serialize.
		ch <- &pb.SnapshotChunk{Size: c.Size, ContentId: c.ContentId, Offset: c.Offset, Data: bytes.Clone(c.Data)}
		return nil
	}
	recv := func() (*pb.SnapshotChunk, error) {
		c, ok := <-ch
		if !ok {
			return nil, io.EOF
		}
		return c, nil
	}
	return send, recv, func() { close(ch) }
}

func allocated(t *testing.T, p string) int64 {
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	return st.Blocks * 512
}

func TestSparseRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	f, _ := os.Create(src)
	f.Truncate(64 << 20)
	data := bytes.Repeat([]byte("opendsec"), 300<<10) // 1.2 MB, crossing chunks
	f.WriteAt(data, 3<<20)
	f.WriteAt(make([]byte, 2<<20), 10<<20) // written zeros: allocated, not sent
	f.WriteAt([]byte("tail"), 64<<20-4)
	f.Close()

	send, recv, done := pipe()
	var n int
	counting := func(c *pb.SnapshotChunk) error { n += len(c.Data); return send(c) }
	if err := Send(src, "ext4-x", counting); err != nil {
		t.Fatal(err)
	}
	done()
	dst := filepath.Join(dir, "dst")
	id, err := Receive(recv, dst, nil)
	if err != nil || id != "ext4-x" {
		t.Fatalf("receive: %q %v", id, err)
	}
	a, _ := os.ReadFile(src)
	b, _ := os.ReadFile(dst)
	if !bytes.Equal(a, b) {
		t.Fatal("content differs")
	}
	if n > len(data)+2*zeroRun { // whole blocks around the data
		t.Errorf("sent %d bytes for %d of data", n, len(data)+4)
	}
	if got := allocated(t, dst); got > 4<<20 {
		t.Errorf("received file allocates %d bytes", got)
	}
}

func TestReuse(t *testing.T) {
	dir := t.TempDir()
	have := filepath.Join(dir, "have")
	os.WriteFile(have, []byte("cached"), 0o644)
	src := filepath.Join(dir, "src")
	os.WriteFile(src, []byte("cached"), 0o644)
	send, recv, done := pipe()
	Send(src, "ext4-1", send)
	done()
	dst := filepath.Join(dir, "dst")
	if _, err := Receive(recv, dst, func(id string) string { return map[string]string{"ext4-1": have}[id] }); err != nil {
		t.Fatal(err)
	}
	var a, b unix.Stat_t
	unix.Stat(have, &a)
	unix.Stat(dst, &b)
	if a.Ino != b.Ino {
		t.Fatal("reused file was not linked")
	}
}
