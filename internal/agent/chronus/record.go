package chronus

import (
	"io"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

// Output limits (spec §29.3): a command's output goes through a pipe to
// chronus, which records up to MaxRecord bytes per stream and reads and
// drops the rest, so a runaway command (`yes`) neither fills the disk
// holding the records (on a container, the host's) nor blocks. A session
// keeps up to SessionRecords bytes of records; past it the oldest finished
// commands' records go.
const (
	DefaultMaxRecord      = 64 << 20
	DefaultSessionRecords = 512 << 20
)

// recorder copies one output stream of a command from its pipe into its
// record file.
type recorder struct {
	pipe, path string
	limit      int64
	opened     chan struct{} // the shell opened the pipe (or gave up on it)
	done       chan struct{} // the stream ended
	dropped    atomic.Int64
}

func startRecorder(pipe, path string, limit int64) *recorder {
	r := &recorder{pipe: pipe, path: path, limit: limit, opened: make(chan struct{}), done: make(chan struct{})}
	go r.run()
	return r
}

func (r *recorder) run() {
	defer close(r.done)
	in, err := os.OpenFile(r.pipe, os.O_RDONLY, 0) // until the shell opens it to write
	close(r.opened)
	os.Remove(r.pipe) // both ends are open: the name has served
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.OpenFile(r.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		r.drop(in)
		return
	}
	n, _ := io.Copy(out, io.LimitReader(in, r.limit))
	out.Close()
	if n == r.limit {
		r.drop(in)
	}
}

func (r *recorder) drop(in io.Reader) {
	n, _ := io.Copy(io.Discard, in)
	r.dropped.Add(n)
}

// release unblocks a recorder whose pipe the shell never opened (the
// command did not run): an empty write end gives it end of file.
func (r *recorder) release() {
	select {
	case <-r.opened:
		return
	default:
	}
	if w, err := os.OpenFile(r.pipe, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
		w.Close()
	}
}

// wait waits up to d for the stream to end: a background process the
// command started may still hold it open.
func (r *recorder) wait(d time.Duration) bool {
	select {
	case <-r.done:
		return true
	case <-time.After(d):
		return false
	}
}
