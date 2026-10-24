package aether

import (
	"os"
	"os/signal"
	"syscall"
)

func signalNotify(c chan os.Signal) {
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGCHLD)
}
