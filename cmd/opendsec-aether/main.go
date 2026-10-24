// opendsec-aether is the per-sandbox proxy. It runs inside the sandbox, normally
// as PID 1 with --init, and serves the Runtime API on a Unix socket, or on
// vsock in a microVM (where --vm-init first assembles the guest's rootfs).
// Built static (CGO_ENABLED=0) so it runs in any rootfs.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"google.golang.org/grpc"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/agent/aether"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--init" {
		os.Exit(aether.RunInit(os.Args[2:]))
	}
	if filepath.Base(os.Args[0]) == aether.VMInitName || len(os.Args) > 1 && os.Args[1] == "--vm-init" {
		os.Exit(aether.RunVMInit())
	}
	sock := flag.String("socket", "/.opendsec/run/aether.sock", "unix socket to serve on")
	vsockPort := flag.Uint("vsock-port", 0, "serve on this vsock port instead of the unix socket")
	rundir := flag.String("rundir", "/.opendsec/run", "runtime directory")
	chronus := flag.String("chronus", "", "opendsec-chronus binary (default: next to this binary)")
	workdir := flag.String("workdir", "/", "initial working directory of sessions")
	user := flag.String("user", "", "user sessions run as")
	env := flag.String("env", "{}", "JSON object of environment variables")
	flag.Parse()

	var envMap map[string]string
	if err := json.Unmarshal([]byte(*env), &envMap); err != nil {
		fmt.Fprintln(os.Stderr, "aether: --env:", err)
		os.Exit(2)
	}
	if *chronus == "" {
		self, _ := os.Executable()
		*chronus = filepath.Join(filepath.Dir(self), "opendsec-chronus")
	}
	a := aether.New(aether.Config{RunDir: *rundir, ChronusBin: *chronus, Workdir: *workdir, User: *user, Env: envMap})
	var lis net.Listener
	var err error
	if *vsockPort > 0 {
		lis, err = aether.ListenVsock(uint32(*vsockPort))
	} else {
		os.Remove(*sock)
		lis, err = net.Listen("unix", *sock)
		os.Chmod(*sock, 0o600)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "aether:", err)
		os.Exit(1)
	}
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(80<<20), grpc.MaxSendMsgSize(80<<20))
	pb.RegisterRuntimeServer(srv, a)
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
		<-c
		srv.Stop()
	}()
	srv.Serve(lis)
	a.CloseAll()
}
