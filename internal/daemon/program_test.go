package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"ethmirror/internal/mirror"
)

func TestStopWaitsForCleanup(t *testing.T) {
	cleanupStarted := make(chan struct{})
	releaseCleanup := make(chan struct{})
	cleanupErr := errors.New("detach failed")
	p := newProgram(mirror.Options{}, func(ctx context.Context, _ mirror.Options) error {
		<-ctx.Done()
		close(cleanupStarted)
		<-releaseCleanup
		return cleanupErr
	})
	if err := p.Start(nil); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- p.Stop(nil) }()
	select {
	case <-cleanupStarted:
	case <-time.After(time.Second):
		t.Fatal("Stop did not cancel the worker")
	}
	select {
	case <-stopped:
		t.Fatal("Stop returned before XDP/TC cleanup completed")
	default:
	}
	close(releaseCleanup)
	select {
	case err := <-stopped:
		if !errors.Is(err, cleanupErr) {
			t.Fatalf("cleanup error was lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not return after cleanup")
	}
}

func TestWorkerFailureEndsServiceWait(t *testing.T) {
	want := errors.New("BPF verifier rejected the program")
	p := newProgram(mirror.Options{}, func(context.Context, mirror.Options) error { return want })
	if err := p.Start(nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p.wait(ctx)
	if ctx.Err() != nil {
		t.Fatal("service remained alive after the mirror worker failed")
	}
	if err := p.Stop(nil); !errors.Is(err, want) {
		t.Fatalf("worker failure was lost: %v", err)
	}
}

func TestServiceWaitEndsOnCancellation(t *testing.T) {
	p := newProgram(mirror.Options{}, func(ctx context.Context, _ mirror.Options) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if err := p.Start(nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.wait(ctx)
	if err := p.Stop(nil); err != nil {
		t.Fatalf("normal cancellation should succeed: %v", err)
	}
}

func TestCancellationDoesNotHideDetachError(t *testing.T) {
	detachErr := errors.New("TC detach failed")
	p := newProgram(mirror.Options{}, func(context.Context, mirror.Options) error {
		return errors.Join(context.Canceled, detachErr)
	})
	if err := p.Start(nil); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(nil); !errors.Is(err, detachErr) {
		t.Fatalf("cancellation hid a cleanup failure: %v", err)
	}
}
