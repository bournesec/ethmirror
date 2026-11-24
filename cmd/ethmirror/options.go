package main

import (
	"errors"
	"flag"
	"fmt"
	"math"
	"time"

	"ethmirror/internal/mirror"
)

func parseOptions(args []string) (mirror.Options, error) {
	var opts mirror.Options
	flags := flag.NewFlagSet("ethmirror", flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: ethmirror [options]")
		fmt.Fprintln(flags.Output(), "       ethmirror service <install|uninstall|start|stop|restart|status> [options]")
		fmt.Fprintln(flags.Output(), "Options (also accepted by service install):")
		flags.PrintDefaults()
	}
	flags.StringVar(&opts.Ingress, "ingress", "eth0", "ingress mirror interface")
	flags.StringVar(&opts.Egress, "egress", "eth1", "interface transmitting cloned frames")
	flags.StringVar(&opts.XDPMode, "xdp-mode", "native", "XDP mode: native or skb")
	seconds := flags.Uint64("stats-interval", 5, "cumulative statistics interval in seconds")
	priority := flags.Uint("tc-priority", 100, "unused TC filter priority (1..65535)")
	handle := flags.Uint64("tc-handle", 1, "unused TC filter handle (1..4294967295)")
	if err := flags.Parse(args); err != nil {
		return opts, err
	}
	if flags.NArg() != 0 {
		return opts, fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	if opts.Ingress == "" || opts.Egress == "" {
		return opts, errors.New("ingress and egress names cannot be empty")
	}
	if opts.XDPMode != "native" && opts.XDPMode != "skb" {
		return opts, errors.New("--xdp-mode must be native or skb")
	}
	if *seconds == 0 || *seconds > uint64(math.MaxInt64/int64(time.Second)) {
		return opts, errors.New("--stats-interval must be a positive number of seconds within time.Duration range")
	}
	if *priority == 0 || *priority > math.MaxUint16 || *handle == 0 || *handle > math.MaxUint32 {
		return opts, errors.New("TC priority must be 1..65535 and handle 1..4294967295")
	}
	opts.StatsInterval = time.Duration(*seconds) * time.Second
	opts.TCPriority, opts.TCHandle = uint16(*priority), uint32(*handle)
	return opts, nil
}
