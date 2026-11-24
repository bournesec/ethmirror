package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"ethmirror/internal/daemon"
	"ethmirror/internal/mirror"

	"github.com/cilium/ebpf"
)

func main() {
	err := execute(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ethmirror: %v\n", err)
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			fmt.Fprintf(os.Stderr, "verifier: %+v\n", verifierErr)
		}
		os.Exit(1)
	}
}

func execute(args []string) error {
	if len(args) > 0 {
		if args[0] == "service" {
			return serviceCommand(args[1:])
		}
		if daemon.IsControlAction(args[0]) {
			return serviceCommand(args)
		}
	}
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return mirror.Run(ctx, opts)
}
