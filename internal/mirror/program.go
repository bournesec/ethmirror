package mirror

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	xdpProgramName = "ethmirror_xdp"
	tcProgramName  = "ethmirror_tc"
	statsMapName   = "stats"
	targetMapName  = "tx_ifindex"
	xdpPass        = 2
	tcUnspec       = -1
	statsSize      = 48
)

// All fields are u64 and have fixed offsets shared with the eBPF instructions.
type statistics struct {
	XDPPackets   uint64
	XDPBytes     uint64
	TCPackets    uint64
	CloneOK      uint64
	CloneErrors  uint64
	Unconfigured uint64
}

func collectionSpec() *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			targetMapName: {Name: targetMapName, Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1},
			statsMapName:  {Name: statsMapName, Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: statsSize, MaxEntries: 1},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			xdpProgramName: {Name: xdpProgramName, Type: ebpf.XDP, License: "GPL", Instructions: xdpInstructions()},
			tcProgramName:  {Name: tcProgramName, Type: ebpf.SchedCLS, License: "GPL", Instructions: mirrorInstructions()},
		},
	}
}

// lookupZero uses a fully initialized, aligned u32 key on the BPF stack.
func lookupZero(name string) asm.Instructions {
	return asm.Instructions{
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, 0).WithReference(name),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
	}
}

// R0 is a checked per-CPU map pointer. No atomic instructions are needed.
func increment(offset int16) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R1, asm.R0, offset, asm.DWord),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R0, offset, asm.R1, asm.DWord),
	}
}

// Emit only classic eBPF instructions supported by Linux 4.19: no JMP32,
// bounded loops, BPF-to-BPF calls, global data maps, BTF or CO-RE relocations.
func xdpInstructions() asm.Instructions {
	ins := asm.Instructions{
		// xdp_md.data_end - xdp_md.data. Subtract before adding to the counter
		// so no pointer participates in the subsequent scalar arithmetic.
		asm.LoadMem(asm.R7, asm.R1, 4, asm.Word),
		asm.LoadMem(asm.R8, asm.R1, 0, asm.Word),
		asm.Sub.Reg(asm.R7, asm.R8),
	}
	ins = append(ins, lookupZero(statsMapName)...)
	ins = append(ins, asm.JEq.Imm(asm.R0, 0, "xdp_exit"))
	ins = append(ins, increment(0)...)
	ins = append(ins,
		asm.LoadMem(asm.R1, asm.R0, 8, asm.DWord),
		asm.Add.Reg(asm.R1, asm.R7),
		asm.StoreMem(asm.R0, 8, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, xdpPass).WithSymbol("xdp_exit"),
		asm.Return(),
	)
	return ins
}

func mirrorInstructions() asm.Instructions {
	ins := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1), // preserve skb context across map lookup
		asm.Mov.Imm(asm.R7, 40),     // unconfigured counter offset
	}
	ins = append(ins, lookupZero(targetMapName)...)
	ins = append(ins,
		asm.JEq.Imm(asm.R0, 0, "tc_count"),
		asm.LoadMem(asm.R2, asm.R0, 0, asm.Word),
		asm.JEq.Imm(asm.R2, 0, "tc_count"),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R3, 0), // flags=0: clone to egress, not ingress
		asm.FnCloneRedirect.Call(),
		asm.Mov.Imm(asm.R7, 32),
		asm.JNE.Imm(asm.R0, 0, "tc_count"), // negative AND positive errors
		asm.Mov.Imm(asm.R7, 24),
	)
	count := lookupZero(statsMapName)
	count[0] = count[0].WithSymbol("tc_count")
	ins = append(ins, count...)
	ins = append(ins, asm.JEq.Imm(asm.R0, 0, "tc_exit"))
	ins = append(ins, increment(16)...)
	ins = append(ins,
		asm.JEq.Imm(asm.R7, 24, "tc_ok"),
		asm.JEq.Imm(asm.R7, 32, "tc_error"),
	)
	ins = append(ins, increment(40)...)
	ins = append(ins, asm.Ja.Label("tc_exit"))
	ok := increment(24)
	ok[0] = ok[0].WithSymbol("tc_ok")
	ins = append(ins, ok...)
	ins = append(ins, asm.Ja.Label("tc_exit"))
	failure := increment(32)
	failure[0] = failure[0].WithSymbol("tc_error")
	ins = append(ins, failure...)
	ins = append(ins,
		// Original reception and later TC filters continue, including on errors.
		asm.Mov.Imm(asm.R0, tcUnspec).WithSymbol("tc_exit"),
		asm.Return(),
	)
	return ins
}
