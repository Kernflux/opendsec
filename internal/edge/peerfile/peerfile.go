// Package peerfile streams files from one edge to another (spec §26),
// sending only their data: snapshot memory files and disks are mostly holes
// and zero pages, which stay holes on the receiving side.
package peerfile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
)

// chunk is the most data one message carries.
const chunk = 1 << 20

// zeroRun is the granularity at which runs of zeros inside data extents are
// skipped (pages a guest gave back, never-written disk blocks).
const zeroRun = 64 << 10

var zeros = make([]byte, zeroRun)

// Send streams the file at path: first its size and contentID, then each
// run of non-zero data with its offset.
func Send(path, contentID string, send func(*pb.SnapshotChunk) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	size := st.Size()
	if err := send(&pb.SnapshotChunk{Size: size, ContentId: contentID}); err != nil {
		return err
	}
	buf := make([]byte, chunk)
	fd := int(f.Fd())
	for off := int64(0); off < size; {
		data, err := unix.Seek(fd, off, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			break // only a hole is left
		}
		if err != nil {
			data = off // no SEEK_DATA: treat the rest as data
		}
		end, err := unix.Seek(fd, data, unix.SEEK_HOLE)
		if err != nil || end > size {
			end = size
		}
		for o := data; o < end; {
			n, err := f.ReadAt(buf[:min(chunk, end-o)], o)
			if n == 0 && err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			if err := sendNonZero(buf[:n], o, send); err != nil {
				return err
			}
			o += int64(n)
		}
		off = end
	}
	return nil
}

// sendNonZero sends b (at offset off) without its zero runs.
func sendNonZero(b []byte, off int64, send func(*pb.SnapshotChunk) error) error {
	start := -1
	flush := func(to int) error {
		if start < 0 {
			return nil
		}
		err := send(&pb.SnapshotChunk{Offset: off + int64(start), Data: b[start:to]})
		start = -1
		return err
	}
	for i := 0; i < len(b); i += zeroRun {
		j := min(i+zeroRun, len(b))
		if bytes.Equal(b[i:j], zeros[:j-i]) {
			if err := flush(i); err != nil {
				return err
			}
		} else if start < 0 {
			start = i
		}
	}
	return flush(len(b))
}

// Receive writes a stream made by Send to dst (created with mode 0644) and
// returns the file's content id. reuse, if set, is offered the content id
// first: a path it returns is linked to dst and the rest of the stream is
// not read (the caller cancels it).
func Receive(recv func() (*pb.SnapshotChunk, error), dst string, reuse func(contentID string) string) (string, error) {
	head, err := recv()
	if err != nil {
		return "", err
	}
	if head.ContentId != "" && reuse != nil {
		if p := reuse(head.ContentId); p != "" {
			if err := os.Link(p, dst); err == nil {
				return head.ContentId, nil
			}
		}
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return "", err
	}
	if err := f.Truncate(head.Size); err != nil {
		f.Close()
		return "", err
	}
	for {
		c, err := recv()
		if err == io.EOF {
			break
		}
		if err == nil && c.Offset+int64(len(c.Data)) > head.Size {
			err = fmt.Errorf("chunk at %d beyond the %d-byte file", c.Offset, head.Size)
		}
		if err == nil {
			_, err = f.WriteAt(c.Data, c.Offset)
		}
		if err != nil {
			f.Close()
			return "", err
		}
	}
	return head.ContentId, f.Close()
}
