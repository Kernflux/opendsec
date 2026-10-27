package chronus

import (
	"io"
	"os"
	"sync"
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
// record file. What it writes counts in the session's total as it is
// written: a background process the command left keeps writing after it
// ends, and that output is held to the session's budget too.
type recorder struct {
	pipe, path string
	limit      int64
	total      *atomic.Int64 // the session's records, in bytes
	grew       func()        // called when the total grew
	opened     chan struct{} // the shell opened the pipe (or gave up on it)
	done       chan struct{} // the stream ended
	dropped    atomic.Int64

	mu      sync.Mutex
	size    int64 // written to the record and counted in total
	removed bool  // the record went (session budget): the rest is dropped
}

func startRecorder(pipe, path string, limit int64, total *atomic.Int64, grew func()) *recorder {
	r := &recorder{pipe: pipe, path: path, limit: limit, total: total, grew: grew, opened: make(chan struct{}), done: make(chan struct{})}
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
	defer out.Close()
	buf := make([]byte, 64<<10)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			r.mu.Lock()
			keep := int64(n)
			if r.removed {
				keep = 0
			}
			keep = min(keep, r.limit-r.size)
			if keep > 0 {
				w, _ := out.Write(buf[:keep])
				r.size += int64(w)
				r.total.Add(int64(w))
			}
			r.mu.Unlock()
			if int64(n) > keep {
				r.dropped.Add(int64(n) - keep)
			}
			if keep > 0 && r.grew != nil {
				r.grew()
			}
		}
		if err != nil {
			return
		}
	}
}

// remove takes the record out of the session's total; what the stream
// carries from now on is dropped. The caller removes the file.
func (r *recorder) remove() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.removed {
		r.removed = true
		r.total.Add(-r.size)
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
