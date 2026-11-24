//go:build !linux

package mirror

import (
	"context"
	"errors"
)

// Run requires Linux with XDP and TC support.
func Run(ctx context.Context, opts Options) error {
	return errors.New("ethmirror requires Linux 4.19 or newer")
}
