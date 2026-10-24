package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/cluster"
	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/rpcutil"
	"github.com/kernflux/opendsec/pkg/client"
)

// bench measures creation throughput/latency and placement balance on an
// in-process cluster of sim edges (spec §8). Every creation goes through the
// full path over real gRPC: SDK -> apiserver -> IAM admit -> placement -> edge.
func bench(args []string) error {
	for _, a := range args {
		if a == "-target" || strings.HasPrefix(a, "-target=") || a == "--target" || strings.HasPrefix(a, "--target=") {
			return benchTarget(args)
		}
	}
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	edges := fs.Int("edges", 100, "sim edges")
	apis := fs.Int("apiservers", 1, "apiserver instances")
	n := fs.Int("n", 20000, "sandboxes to create")
	conc := fs.Int("c", 256, "concurrent creators")
	k := fs.Int("k", 2, "power-of-k (1 = random placement)")
	compare := fs.Bool("compare", false, "run with k=1 and with -k, and compare")
	latency := fs.Float64("latency-ms", 0, "sim backend median create latency")
	cpu := fs.Float64("cpu", 1, "cpu cores per sandbox")
	mem := fs.Int64("mem", 2048, "memory MB per sandbox")
	edgeCPU := fs.Float64("edge-cpu", 192, "physical cores per edge (x8 overcommit)")
	edgeMem := fs.Int64("edge-mem", 1536*1024, "memory MB per edge")
	maxSb := fs.Int("max", 3200, "max sandboxes per edge")
	cpuProfile := fs.String("cpuprofile", "", "write a CPU profile here")
	iamReplicas := fs.Int("iam-replicas", 0, "run IAM replicated with Raft over this many replicas (0 = standalone)")
	fs.Parse(args)
	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			return err
		}
		defer f.Close()
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	ks := []int{*k}
	if *compare {
		ks = []int{1, *k}
	}
	fmt.Printf("bench: %d sim edges, %d apiserver(s), %d sandboxes, concurrency %d, GOMAXPROCS=%d, iam replicas=%d\n",
		*edges, *apis, *n, *conc, runtime.GOMAXPROCS(0), *iamReplicas)
	for _, kk := range ks {
		cfg := cluster.SimConfig(*edges, *apis, *edgeCPU, *edgeMem, int32(*maxSb))
		cfg.Placement.K = kk
		if *iamReplicas > 0 {
			dir, err := os.MkdirTemp("", "opendsec-bench-iam")
			if err != nil {
				return err
			}
			defer os.RemoveAll(dir)
			cfg.IAM.AdminToken = "dsk.admin.bench-secret"
			for r := 0; r < *iamReplicas; r++ {
				cfg.IAM.Replicas = append(cfg.IAM.Replicas, config.IAMReplica{ID: fmt.Sprint(r),
					Addr: "127.0.0.1:0", RaftAddr: "127.0.0.1:0", DataDir: fmt.Sprintf("%s/%d", dir, r)})
			}
		}
		for i := range cfg.Edges {
			cfg.Edges[i].Backends["sim"] = config.Backend{MaxSandboxes: int32(*maxSb), CreateLatencyMs: *latency, LatencySigma: 0.5}
		}
		if err := benchOnce(cfg, *n, *conc, &pb.Resources{CpuCores: *cpu, MemoryMb: *mem}); err != nil {
			return err
		}
	}
	return nil
}

func benchOnce(cfg *config.Cluster, n, conc int, res *pb.Resources) error {
	l, err := cluster.StartLocal(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return err
	}
	defer l.Stop()
	var clients []*client.Client
	for _, a := range cfg.APIServers {
		c, err := client.Dial(a.Addr, l.AdminToken, "root")
		if err != nil {
			return err
		}
		defer c.Close()
		clients = append(clients, c)
	}
	spec := &pb.SandboxSpec{Backend: "sim", Resources: res, TaskId: "bench"}

	var next atomic.Int64
	lat := make([]time.Duration, n)
	var mu sync.Mutex
	fails := map[string]int{}
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			c := clients[w%len(clients)]
			for {
				i := next.Add(1) - 1
				if i >= int64(n) {
					return
				}
				t0 := time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				_, err := c.Create(ctx, spec)
				cancel()
				lat[i] = time.Since(t0)
				if err != nil {
					mu.Lock()
					fails[rpcutil.Reason(err)]++
					mu.Unlock()
				}
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)

	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) time.Duration { return lat[min(len(lat)-1, int(p*float64(len(lat))))] }

	var counts []float64
	var rejected int64
	for _, e := range l.Edges {
		st := e.Status(false).State
		counts = append(counts, float64(st.CountByBackend["sim"]))
		rejected += st.TotalRejected
	}
	mean, maxC, sd := stats(counts)
	ok := n - sum(fails)
	fmt.Printf("\nk=%d  created %d/%d in %v  ->  %.0f creates/s\n", cfg.Placement.K, ok, n,
		elapsed.Round(time.Millisecond), float64(ok)/elapsed.Seconds())
	fmt.Printf("  latency   p50 %v  p95 %v  p99 %v  max %v\n",
		pct(.50).Round(10*time.Microsecond), pct(.95).Round(10*time.Microsecond),
		pct(.99).Round(10*time.Microsecond), lat[len(lat)-1].Round(10*time.Microsecond))
	fmt.Printf("  balance   sandboxes/edge mean %.1f  max %.0f  stddev %.2f  max/mean %.3f\n", mean, maxC, sd, maxC/mean)
	fmt.Printf("  edge rejections (retried elsewhere) %d   failures %v\n", rejected, fails)
	return nil
}

func stats(xs []float64) (mean, maxV, sd float64) {
	for _, x := range xs {
		mean += x
		maxV = math.Max(maxV, x)
	}
	mean /= float64(len(xs))
	for _, x := range xs {
		sd += (x - mean) * (x - mean)
	}
	return mean, maxV, math.Sqrt(sd / float64(len(xs)))
}
