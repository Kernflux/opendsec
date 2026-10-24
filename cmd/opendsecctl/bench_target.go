package main

import (
	"context"
	"flag"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

// benchTarget loads a running cluster (opendsecctl bench -target ADDR[,ADDR]):
// n creations by c concurrent workers, one at a time or in batches, with
// the rate printed every 5 s so a slowdown as the cluster fills shows. Then
// the placement balance from the cluster snapshot and, with -stop, the time
// to stop the whole task.
func benchTarget(args []string) error {
	fs := flag.NewFlagSet("bench -target", flag.ExitOnError)
	target := fs.String("target", "", "apiserver address(es), comma separated")
	token := fs.String("token", "", "bearer token (default $OPENDSEC_TOKEN)")
	ca := fs.String("ca", "", "CA certificate (default $OPENDSEC_CA)")
	project := fs.String("project", "root", "project")
	backend := fs.String("backend", "sim", "sandbox backend")
	image := fs.String("image", "", "image")
	n := fs.Int("n", 20000, "sandboxes to create")
	conc := fs.Int("c", 256, "concurrent creators (or concurrent batches)")
	batch := fs.Int("batch", 0, "create in batches of this size (CreateSandboxes); 0 = one at a time")
	cpu := fs.Float64("cpu", 1, "cpu cores per sandbox")
	mem := fs.Int64("mem", 512, "memory MB per sandbox")
	task := fs.String("task", "bench", "task id of the sandboxes")
	stop := fs.Bool("stop", false, "stop the task's sandboxes afterwards, and time it")
	fs.Parse(args)
	if *token == "" {
		*token = envOr("OPENDSEC_TOKEN", "")
	}
	if *ca == "" {
		*ca = envOr("OPENDSEC_CA", "")
	}
	var opts []client.Option
	if *ca != "" {
		opts = append(opts, client.WithCAFile(*ca))
	}
	// One connection per apiserver, workers spread over them, as many
	// independent clients would.
	var clients []*client.Client
	for _, a := range strings.Split(*target, ",") {
		c, err := client.Dial(strings.TrimSpace(a), *token, *project, opts...)
		if err != nil {
			return err
		}
		defer c.Close()
		clients = append(clients, c)
	}
	spec := &pb.SandboxSpec{Backend: *backend, Image: *image, TaskId: *task,
		Resources: &pb.Resources{CpuCores: *cpu, MemoryMb: *mem}}
	fmt.Printf("bench -target %s: %d %s sandboxes, concurrency %d, batch %d, %d apiserver connection(s)\n",
		*target, *n, *backend, *conc, *batch, len(clients))

	var created, failed atomic.Int64
	var next atomic.Int64
	var mu sync.Mutex
	var lat []time.Duration
	fails := map[string]int{}
	note := func(err error) {
		mu.Lock()
		fails[rpcutil.Reason(err)+": "+firstLine(rpcutil.Message(err))]++
		mu.Unlock()
	}
	done := make(chan struct{})
	start := time.Now()
	go func() { // progress
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		last, lastT := int64(0), start
		for {
			select {
			case <-done:
				return
			case now := <-t.C:
				c := created.Load()
				fmt.Printf("  %6.0fs  created %8d  failed %6d  rate %7.0f/s\n", now.Sub(start).Seconds(), c, failed.Load(),
					float64(c-last)/now.Sub(lastT).Seconds())
				last, lastT = c, now
			}
		}
	}()
	var wg sync.WaitGroup
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			c := clients[w%len(clients)]
			step := int64(max(*batch, 1))
			for {
				i := next.Add(step) - step
				if i >= int64(*n) {
					return
				}
				k := min(step, int64(*n)-i)
				t0 := time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
				if *batch == 0 {
					_, err := c.Create(ctx, spec)
					if err != nil {
						failed.Add(1)
						note(err)
					} else {
						created.Add(1)
					}
				} else {
					res, err := c.CreateBatch(ctx, spec, int32(k))
					ok := int64(0)
					for _, r := range res {
						if r.ErrorReason == "" {
							ok++
						} else {
							mu.Lock()
							fails[r.ErrorReason]++
							mu.Unlock()
						}
					}
					if err != nil {
						note(err)
					}
					created.Add(ok)
					failed.Add(k - ok)
				}
				cancel()
				mu.Lock()
				lat = append(lat, time.Since(t0))
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	close(done)
	elapsed := time.Since(start)
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) time.Duration {
		if len(lat) == 0 {
			return 0
		}
		return lat[min(len(lat)-1, int(p*float64(len(lat))))].Round(100 * time.Microsecond)
	}
	unit := "create"
	if *batch > 0 {
		unit = fmt.Sprintf("batch of %d", *batch)
	}
	fmt.Printf("\ncreated %d/%d in %v -> %.0f/s; failed %d\n", created.Load(), *n, elapsed.Round(time.Millisecond),
		float64(created.Load())/elapsed.Seconds(), failed.Load())
	fmt.Printf("latency per %s: p50 %v  p95 %v  p99 %v  max %v\n", unit, pct(.5), pct(.95), pct(.99), pct(1))
	for k, v := range fails {
		fmt.Printf("  failure x%d: %s\n", v, k)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	t0 := time.Now()
	snap, err := clients[0].ClusterStatus(ctx, &pb.Empty{})
	if err != nil {
		return err
	}
	var counts []float64
	total := 0.0
	for _, e := range snap.Edges {
		v := float64(e.CountByBackend[*backend])
		counts = append(counts, v)
		total += v
	}
	mean, maxC, sd := stats(counts)
	fmt.Printf("cluster: %d edges, %.0f %s sandboxes; per edge mean %.1f max %.0f stddev %.2f max/mean %.3f (snapshot %v, %d bytes)\n",
		len(snap.Edges), total, *backend, mean, maxC, sd, maxC/max(mean, 1e-9), time.Since(t0).Round(time.Millisecond), protoSize(snap))

	if *stop {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		t0 := time.Now()
		r, err := clients[0].ApplyTaskAction(ctx, &pb.TaskActionRequest{Project: *project, TaskId: *task, Action: pb.TaskAction_TASK_STOP})
		if err != nil {
			return err
		}
		fmt.Printf("stopped task %s: %v in %v\n", *task, r, time.Since(t0).Round(time.Millisecond))
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

func protoSize(m proto.Message) int { return proto.Size(m) }
