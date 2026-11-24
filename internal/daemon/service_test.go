package daemon

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"ethmirror/internal/mirror"

	"github.com/kardianos/service"
)

type fakeService struct {
	service.Service // unused methods must never be called by control tests
	calls           []string
	status          service.Status
	statusErr       error
	stopErr         error
}

func (s *fakeService) Platform() string { return "test-service" }
func (s *fakeService) Status() (service.Status, error) {
	s.calls = append(s.calls, "status")
	return s.status, s.statusErr
}
func (s *fakeService) Install() error   { s.calls = append(s.calls, "install"); return nil }
func (s *fakeService) Uninstall() error { s.calls = append(s.calls, "uninstall"); return nil }
func (s *fakeService) Start() error     { s.calls = append(s.calls, "start"); return nil }
func (s *fakeService) Restart() error   { s.calls = append(s.calls, "restart"); return nil }
func (s *fakeService) Stop() error {
	s.calls = append(s.calls, "stop")
	return s.stopErr
}

func TestControlDelegatesToLibrary(t *testing.T) {
	for _, action := range []string{"install", "start", "stop", "restart"} {
		t.Run(action, func(t *testing.T) {
			s := &fakeService{}
			var out bytes.Buffer
			if err := control(s, action, &out); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(s.calls, []string{action}) {
				t.Fatalf("unexpected service operations: %v", s.calls)
			}
		})
	}
}

func TestUninstallStopsBeforeRemovingService(t *testing.T) {
	stopErr := errors.New("stop denied")
	for _, tt := range []struct {
		name      string
		status    service.Status
		statusErr error
		stopErr   error
		wantCalls []string
		wantErr   error
	}{
		{"running", service.StatusRunning, nil, nil, []string{"status", "stop", "uninstall"}, nil},
		{"stopped", service.StatusStopped, nil, nil, []string{"status", "uninstall"}, nil},
		{"failed", service.StatusUnknown, errors.New("failed state"), nil, []string{"status", "stop", "uninstall"}, nil},
		{"stop failure", service.StatusRunning, nil, stopErr, []string{"status", "stop"}, stopErr},
		{"not installed", service.StatusUnknown, service.ErrNotInstalled, nil, []string{"status"}, service.ErrNotInstalled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := &fakeService{status: tt.status, statusErr: tt.statusErr, stopErr: tt.stopErr}
			var out bytes.Buffer
			if err := control(s, "uninstall", &out); !errors.Is(err, tt.wantErr) {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(s.calls, tt.wantCalls) {
				t.Fatalf("unsafe uninstall order: %v", s.calls)
			}
		})
	}
}

func TestStatusDoesNotModifyService(t *testing.T) {
	for _, tt := range []struct {
		status service.Status
		err    error
		label  string
	}{
		{service.StatusRunning, nil, "running"},
		{service.StatusStopped, nil, "stopped"},
		{service.StatusUnknown, service.ErrNotInstalled, "not installed"},
	} {
		s := &fakeService{status: tt.status, statusErr: tt.err}
		var out bytes.Buffer
		if err := control(s, "status", &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), tt.label) || !reflect.DeepEqual(s.calls, []string{"status"}) {
			t.Fatalf("unexpected status result: %q, calls %v", out.String(), s.calls)
		}
	}
}

func TestInstallSavesAllMirrorOptions(t *testing.T) {
	cfg := config(mirror.Options{Ingress: "ens1", Egress: "ens2", XDPMode: "skb", StatsInterval: 17 * time.Second, TCPriority: 205, TCHandle: 0x1234})
	want := []string{"service", "run", "--ingress", "ens1", "--egress", "ens2", "--xdp-mode", "skb", "--stats-interval", "17", "--tc-priority", "205", "--tc-handle", "4660"}
	if !reflect.DeepEqual(cfg.Arguments, want) {
		t.Fatalf("saved service options differ: %v", cfg.Arguments)
	}
	if cfg.Name != Name || cfg.UserName != "root" || cfg.Option["Restart"] != "on-failure" {
		t.Fatalf("unexpected service configuration: %+v", cfg)
	}
}
