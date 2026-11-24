package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"ethmirror/internal/mirror"

	"github.com/kardianos/service"
)

const Name = "ethmirror"

// IsControlAction reports the public service management commands.
func IsControlAction(action string) bool {
	switch action {
	case "install", "uninstall", "start", "stop", "restart", "status":
		return true
	default:
		return false
	}
}

func config(opts mirror.Options) *service.Config {
	return &service.Config{
		Name:        Name,
		DisplayName: "Ethernet Traffic Mirror",
		Description: "Mirror ingress Ethernet traffic while retaining local reception",
		UserName:    "root",
		Arguments: []string{
			"service", "run",
			"--ingress", opts.Ingress,
			"--egress", opts.Egress,
			"--xdp-mode", opts.XDPMode,
			"--stats-interval", strconv.FormatInt(int64(opts.StatsInterval/time.Second), 10),
			"--tc-priority", strconv.FormatUint(uint64(opts.TCPriority), 10),
			"--tc-handle", strconv.FormatUint(uint64(opts.TCHandle), 10),
		},
		Dependencies: []string{"Wants=network-online.target", "After=network-online.target"},
		Option:       service.KeyValue{"Restart": "on-failure"},
	}
}

func newService(p *program, cfg *service.Config) (service.Service, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("ethmirror service management requires Linux")
	}
	svc, err := service.New(p, cfg)
	if err != nil {
		return nil, fmt.Errorf("create OS service: %w", err)
	}
	return svc, nil
}

// Run is invoked by the installed service with its saved mirror options.
func Run(opts mirror.Options) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	p := newProgram(opts, mirror.Run)
	cfg := config(opts)
	cfg.Option["RunWait"] = func() { p.wait(ctx) }
	svc, err := newService(p, cfg)
	if err != nil {
		return err
	}
	return svc.Run()
}

// Control delegates service registration and lifecycle commands to the library.
func Control(action string, opts mirror.Options, out io.Writer) error {
	if !IsControlAction(action) {
		return fmt.Errorf("unknown service action %q", action)
	}
	svc, err := newService(newProgram(opts, mirror.Run), config(opts))
	if err != nil {
		return err
	}
	return control(svc, action, out)
}

func control(svc service.Service, action string, out io.Writer) error {
	if action == "status" {
		status, err := svc.Status()
		if errors.Is(err, service.ErrNotInstalled) {
			_, err = fmt.Fprintf(out, "%s: not installed\n", Name)
			return err
		}
		if err != nil {
			return fmt.Errorf("query service status: %w", err)
		}
		label := "unknown"
		switch status {
		case service.StatusRunning:
			label = "running"
		case service.StatusStopped:
			label = "stopped"
		}
		_, err = fmt.Fprintf(out, "%s: %s (%s)\n", Name, label, svc.Platform())
		return err
	}
	if action == "uninstall" {
		status, err := svc.Status()
		if errors.Is(err, service.ErrNotInstalled) {
			return err
		}
		// A failed/unknown state may still have a live process. If stop fails,
		// keep the service registered so the administrator can recover it.
		if err != nil || status != service.StatusStopped {
			if err := svc.Stop(); err != nil {
				return fmt.Errorf("stop service before uninstall: %w", err)
			}
		}
	}
	if err := service.Control(svc, action); err != nil {
		return fmt.Errorf("service %s: %w", action, err)
	}
	if action == "install" {
		_, err := fmt.Fprintf(out, "%s: installed (%s); use ethmirror service start to start it\n", Name, svc.Platform())
		return err
	}
	_, err := fmt.Fprintf(out, "%s: %s succeeded\n", Name, action)
	return err
}
