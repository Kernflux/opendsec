// opendsec-chronus serves one shell session inside a sandbox. aether starts one
// per session id. Built static (CGO_ENABLED=0).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/agent/chronus"
)

func main() {
	sock := flag.String("socket", "", "unix socket to serve on")
	session := flag.String("session", "default", "session id")
	workdir := flag.String("workdir", "/", "initial working directory")
	user := flag.String("user", "", "run the shell as this user")
	env := flag.String("env", "{}", "JSON object of environment variables")
	records := flag.String("records", "", "directory for command scripts and output records")
	maxRecord := flag.Int64("max-output-mb", chronus.DefaultMaxRecord>>20, "record at most this much of each output stream of a command")
	sessionRecords := flag.Int64("session-output-mb", chronus.DefaultSessionRecords>>20, "keep at most this much of the session's records")
	flag.Parse()

	var envMap map[string]string
	if err := json.Unmarshal([]byte(*env), &envMap); err != nil {
		fmt.Fprintln(os.Stderr, "chronus: --env:", err)
		os.Exit(2)
	}
	sh, err := chronus.NewShell(*workdir, *user, envMap, *records)
	if err != nil {
		fmt.Fprintln(os.Stderr, "chronus:", err)
		os.Exit(1)
	}
	sh.MaxRecord, sh.SessionRecords = *maxRecord<<20, *sessionRecords<<20
	defer sh.Close()
	if err := chronus.BecomeSubreaper(sh.IsShell); err != nil {
		fmt.Fprintln(os.Stderr, "chronus: subreaper:", err)
	}
	os.Remove(*sock)
	lis, err := net.Listen("unix", *sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "chronus:", err)
		os.Exit(1)
	}
	// Only aether (root) talks to chronus: a session's commands, run as
	// another user, cannot forge requests to it (spec §29.3).
	os.Chmod(*sock, 0o600)
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(80<<20), grpc.MaxSendMsgSize(80<<20))
	pb.RegisterRuntimeServer(srv, &chronus.Server{Session: *session, Shell: sh})
	srv.Serve(lis)
}
