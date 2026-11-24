package mirror

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func checkKernel() error {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return fmt.Errorf("read kernel version: %w", err)
	}
	release := unix.ByteSliceToString(uts.Release[:])
	var major, minor int
	if n, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil || n != 2 {
		return fmt.Errorf("cannot parse kernel release %q", release)
	}
	if major < 4 || (major == 4 && minor < 19) {
		return fmt.Errorf("Linux 4.19 or newer is required; running %s", release)
	}
	return nil
}

func printStats(w io.Writer, m *ebpf.Map) error {
	var values []statistics
	if err := m.Lookup(uint32(0), &values); err != nil {
		return fmt.Errorf("read per-CPU statistics: %w", err)
	}
	var total statistics
	for _, cpu := range values {
		total.XDPPackets += cpu.XDPPackets
		total.XDPBytes += cpu.XDPBytes
		total.TCPackets += cpu.TCPackets
		total.CloneOK += cpu.CloneOK
		total.CloneErrors += cpu.CloneErrors
		total.Unconfigured += cpu.Unconfigured
	}
	_, err := fmt.Fprintf(w, "xdp_packets=%d xdp_bytes=%d tc_packets=%d clone_ok=%d clone_errors=%d unconfigured=%d\n",
		total.XDPPackets, total.XDPBytes, total.TCPackets, total.CloneOK, total.CloneErrors, total.Unconfigured)
	return err
}

// Run loads the mirror programs and keeps them attached until ctx is canceled.
func Run(ctx context.Context, opts Options) (retErr error) {
	if err := checkKernel(); err != nil {
		return err
	}
	ingress, err := netlink.LinkByName(opts.Ingress)
	if err != nil {
		return fmt.Errorf("ingress interface %s: %w", opts.Ingress, err)
	}
	egress, err := netlink.LinkByName(opts.Egress)
	if err != nil {
		return fmt.Errorf("egress interface %s: %w", opts.Egress, err)
	}
	if ingress.Attrs().Index == egress.Attrs().Index {
		return errors.New("ingress and egress must be different interfaces")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("raise BPF memory limit (requires sufficient privileges): %w", err)
	}
	collection, err := ebpf.NewCollection(collectionSpec())
	if err != nil {
		return fmt.Errorf("load eBPF programs and maps: %w", err)
	}
	defer collection.Close()
	if err := collection.Maps[targetMapName].Update(uint32(0), uint32(egress.Attrs().Index), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("configure egress ifindex: %w", err)
	}
	attached := &attachment{linkIndex: ingress.Attrs().Index}
	defer func() {
		if err := attached.close(); err != nil {
			retErr = errors.Join(retErr, err)
		} else if attached.ready {
			fmt.Fprintln(os.Stderr, "detached XDP and TC mirror")
		}
	}()
	if err := attached.attach(ingress, collection, opts); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "ready: %s (ifindex %d) -> clone -> %s (ifindex %d); original continues to local stack; XDP %s\n",
		opts.Ingress, ingress.Attrs().Index, opts.Egress, egress.Attrs().Index, opts.XDPMode)
	ticker := time.NewTicker(opts.StatsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return printStats(os.Stderr, collection.Maps[statsMapName])
		case <-ticker.C:
			if err := printStats(os.Stderr, collection.Maps[statsMapName]); err != nil {
				return err
			}
		}
	}
}
