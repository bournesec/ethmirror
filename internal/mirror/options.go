// Package mirror loads and manages ingress traffic mirroring programs.
package mirror

import "time"

// Options configures the ingress and egress interfaces and attachment settings.
type Options struct {
	Ingress       string
	Egress        string
	XDPMode       string
	StatsInterval time.Duration
	TCPriority    uint16
	TCHandle      uint32
}
