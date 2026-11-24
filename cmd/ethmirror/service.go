package main

import (
	"fmt"
	"os"

	"ethmirror/internal/daemon"
)

func serviceCommand(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(os.Stdout, "Usage: ethmirror service <install|uninstall|start|stop|restart|status>")
		fmt.Fprintln(os.Stdout, "Install accepts foreground options; use ethmirror service install --help.")
		return nil
	}
	action := args[0]
	if !daemon.IsControlAction(action) && action != "run" {
		return fmt.Errorf("unknown service action %q (use install, uninstall, start, stop, restart or status)", action)
	}
	// Only install saves configuration. Start/restart use the installed options.
	if action != "install" && action != "run" && len(args) > 1 {
		return fmt.Errorf("service %s does not accept options; configure them with service install", action)
	}
	opts, err := parseOptions(args[1:])
	if err != nil {
		return err
	}
	if action == "run" {
		return daemon.Run(opts)
	}
	return daemon.Control(action, opts, os.Stdout)
}
