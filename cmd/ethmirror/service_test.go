package main

import (
	"errors"
	"flag"
	"strings"
	"testing"
)

// These malformed commands must fail before any OS service operation.
func TestServiceCommandRejectsInvalidArguments(t *testing.T) {
	for _, args := range [][]string{
		{"service", "unknown"},
		{"service", "start", "--egress", "ens2"},
		{"restart", "--xdp-mode", "skb"},
		{"service", "install", "--xdp-mode", "invalid"},
	} {
		if err := execute(args); err == nil {
			t.Fatalf("accepted invalid command: %v", args)
		}
	}
}

func TestServiceInstallHelpDoesNotInstall(t *testing.T) {
	if err := execute([]string{"service", "install", "--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("expected help without OS service access: %v", err)
	}
	if err := execute([]string{"service", "status", "unexpected"}); err == nil || !strings.Contains(err.Error(), "does not accept options") {
		t.Fatalf("unexpected service status argument handling: %v", err)
	}
}
