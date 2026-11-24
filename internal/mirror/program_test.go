package mirror

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Inspect bytecode only: never load BPF or change networking.
func TestLinux419InstructionSet(t *testing.T) {
	for name, prog := range collectionSpec().Programs {
		t.Run(name, func(t *testing.T) {
			for _, endian := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
				insns := append(asm.Instructions(nil), prog.Instructions...)
				var encoded bytes.Buffer
				if err := insns.Marshal(&encoded, endian); err != nil {
					t.Fatalf("resolve and encode bytecode: %v", err)
				}
				if encoded.Len()/8 >= 4096 {
					t.Fatal("exceeds the Linux 4.19 instruction limit")
				}
				for i, ins := range insns {
					if ins.OpCode.Class() == asm.Jump32Class {
						t.Fatalf("instruction %d uses JMP32 (requires Linux 5.1)", i)
					}
					if ins.IsFunctionCall() || ins.IsFunctionReference() || ins.IsKfuncCall() {
						t.Fatalf("instruction %d requires non-classic BPF calls", i)
					}
					if ins.IsBuiltinCall() {
						fn := asm.BuiltinFunc(ins.Constant)
						if fn != asm.FnMapLookupElem && (name != tcProgramName || fn != asm.FnCloneRedirect) {
							t.Fatalf("instruction %d uses an unexpected helper: %v", i, fn)
						}
					}
					if ins.OpCode.Class() == asm.JumpClass && ins.OpCode.JumpOp() != asm.Call && ins.OpCode.JumpOp() != asm.Exit && ins.Offset < 0 {
						t.Fatalf("instruction %d has a back edge (loops are not supported)", i)
					}
				}
			}
			want := int64(xdpPass)
			if prog.Type == ebpf.SchedCLS {
				want = tcUnspec
			}
			last := prog.Instructions[len(prog.Instructions)-2:]
			if last[0].OpCode != asm.Mov.Op(asm.ImmSource) || last[0].Dst != asm.R0 || last[0].Constant != want || last[1].OpCode.JumpOp() != asm.Exit {
				t.Fatal("program does not unconditionally pass the original packet")
			}
		})
	}
}

func TestMapLayout(t *testing.T) {
	typ := reflect.TypeOf(statistics{})
	if binary.Size(statistics{}) != statsSize || typ.Size() != statsSize {
		t.Fatal("statistics layout differs from eBPF counter offsets")
	}
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Offset != uintptr(i*8) {
			t.Fatalf("counter %s has an unexpected offset", typ.Field(i).Name)
		}
	}
	for name, m := range collectionSpec().Maps {
		if m.Type != ebpf.Array && m.Type != ebpf.PerCPUArray {
			t.Fatalf("map %s uses a new map type", name)
		}
		if m.KeySize != 4 || m.MaxEntries != 1 || m.Flags != 0 || m.Key != nil || m.Value != nil {
			t.Fatalf("map %s requires unexpected flags or BTF", name)
		}
	}
}
