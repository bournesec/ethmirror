// Package daemon adapts traffic mirroring to github.com/kardianos/service.
package daemon

import (
	"context"

	"ethmirror/internal/mirror"

	"github.com/kardianos/service"
)

type runner func(context.Context, mirror.Options) error

type program struct {
	opts   mirror.Options
	run    runner
	done   chan struct{}
	cancel context.CancelFunc
	err    error
}

func newProgram(opts mirror.Options, run runner) *program {
	return &program{opts: opts, run: run, done: make(chan struct{})}
}

// Start must return quickly, as required by kardianos/service.
func (p *program) Start(service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go func() {
		p.err = p.run(ctx, p.opts)
		close(p.done)
	}()
	return nil
}

// Stop waits for mirror.Run to detach its XDP and TC programs before exiting.
func (p *program) Stop(service.Service) error {
	p.cancel()
	<-p.done // synchronizes the read of p.err with the worker
	if p.err == context.Canceled {
		return nil
	}
	return p.err
}

// A worker error must end Service.Run instead of leaving a dead service alive.
func (p *program) wait(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-p.done:
	}
}
