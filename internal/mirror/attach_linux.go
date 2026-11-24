package mirror

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type attachment struct {
	linkIndex int
	xdpFlags  int
	xdpID     uint32
	tcID      int
	filter    *netlink.BpfFilter
	xdpAdded  bool
	tcAdded   bool
	ready     bool
}

func programID(prog *ebpf.Program) (uint32, error) {
	info, err := prog.Info()
	if err != nil {
		return 0, err
	}
	id, ok := info.ID()
	if !ok {
		return 0, errors.New("kernel did not report the BPF program ID")
	}
	return uint32(id), nil
}

func (a *attachment) attach(dev netlink.Link, collection *ebpf.Collection, opts Options) error {
	xdp, tc := collection.Programs[xdpProgramName], collection.Programs[tcProgramName]
	var err error
	a.xdpID, err = programID(xdp)
	if err != nil {
		return fmt.Errorf("query XDP program ID: %w", err)
	}
	id, err := programID(tc)
	if err != nil {
		return fmt.Errorf("query TC program ID: %w", err)
	}
	a.tcID = int(id)
	a.xdpFlags = unix.XDP_FLAGS_DRV_MODE
	if opts.XDPMode == "skb" {
		a.xdpFlags = unix.XDP_FLAGS_SKB_MODE
	}
	// Netlink works on 4.19. The flag atomically rejects an existing XDP
	// attachment; no bpf_link or newer expected-FD replacement API is used.
	if err := netlink.LinkSetXdpFdWithFlags(dev, xdp.FD(), a.xdpFlags|unix.XDP_FLAGS_UPDATE_IF_NOEXIST); err != nil {
		return fmt.Errorf("attach XDP to %s (existing XDP is never replaced; try --xdp-mode skb if native is unsupported): %w", opts.Ingress, err)
	}
	a.xdpAdded = true
	qdisc := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: a.linkIndex,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add clsact: %w", err)
	}
	a.filter = &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: a.linkIndex,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    opts.TCHandle,
			Priority:  opts.TCPriority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           tc.FD(),
		Name:         tcProgramName,
		DirectAction: true,
	}
	// FilterAdd uses NLM_F_CREATE|NLM_F_EXCL, never replaces another filter.
	if err := netlink.FilterAdd(a.filter); err != nil {
		return fmt.Errorf("add TC mirror (priority/handle must be unused): %w", err)
	}
	a.tcAdded, a.ready = true, true
	return nil
}

func (a *attachment) close() error {
	if !a.xdpAdded && !a.tcAdded {
		return nil
	}
	dev, err := netlink.LinkByIndex(a.linkIndex)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) || errors.Is(err, unix.ENODEV) {
			return nil // deleting the device also deletes both attachments
		}
		return fmt.Errorf("find ingress for detach: %w", err)
	}
	var failures []error
	if a.tcAdded {
		// Only remove a matching program ID at our priority/handle/protocol.
		filters, err := netlink.FilterList(dev, netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			failures = append(failures, fmt.Errorf("query TC filters for detach: %w", err))
		} else {
			for _, candidate := range filters {
				bpf, ok := candidate.(*netlink.BpfFilter)
				if !ok || bpf.Handle != a.filter.Handle || bpf.Priority != a.filter.Priority || bpf.Protocol != a.filter.Protocol {
					continue
				}
				if bpf.Id != a.tcID {
					failures = append(failures, errors.New("TC filter was replaced externally; leaving it attached"))
					break
				}
				if err := netlink.FilterDel(bpf); err != nil && !errors.Is(err, unix.ENOENT) {
					failures = append(failures, fmt.Errorf("detach TC mirror: %w", err))
				}
				break
			}
		}
	}
	if a.xdpAdded && dev.Attrs().Xdp != nil && dev.Attrs().Xdp.Attached {
		if dev.Attrs().Xdp.ProgId != a.xdpID {
			failures = append(failures, errors.New("XDP program was replaced externally; leaving it attached"))
		} else if err := netlink.LinkSetXdpFdWithFlags(dev, -1, a.xdpFlags); err != nil && !errors.Is(err, unix.ENODEV) {
			failures = append(failures, fmt.Errorf("detach XDP: %w", err))
		}
	}
	// Retain clsact to avoid deleting filters belonging to other programs.
	return errors.Join(failures...)
}
