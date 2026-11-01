package qy8consent

// Branch offsets are relative to the instruction address plus 8 (ARM7 pipeline PC).

func bl(at, to uint32) uint32  { return 0xeb000000 | (to-(at+8))>>2&0xffffff }
func b(at, to uint32) uint32   { return 0xea000000 | (to-(at+8))>>2&0xffffff }
func bne(at, to uint32) uint32 { return 0x1a000000 | (to-(at+8))>>2&0xffffff }

func movw(rd, imm uint32) uint32 {
	return 0xe3000000 | imm>>12<<16 | rd<<12 | imm&0xfff
}

// movImm uses mov Rd,#imm when the rotated 8-bit immediate covers the value, movw otherwise.
func movImm(rd, imm uint32) uint32 {
	for rot := uint32(0); rot < 16; rot++ {
		if v := imm<<(2*rot) | imm>>(32-2*rot); v < 0x100 {
			return 0xe3a00000 | rot<<8 | rd<<12 | v
		}
	}
	return movw(rd, imm)
}

func ldrPC(at, rd, to uint32) uint32 {
	off := to - (at + 8)
	if off > 0xfff {
		panic("patch: literal pool out of reach of ldr")
	}
	return 0xe59f0000 | rd<<12 | off
}

// blOrBTarget decodes a bl/b at at; top is 0xeb for bl, 0xea for b.
func blOrBTarget(at, instr uint32, top uint32) (uint32, bool) {
	if instr>>24 != top {
		return 0, false
	}
	imm := instr & 0xffffff
	signed := int32(imm<<8) >> 6
	return uint32(int32(at+8) + signed), true
}

func decodeBL(at, instr uint32) (uint32, bool) { return blOrBTarget(at, instr, 0xeb) }
func decodeB(at, instr uint32) (uint32, bool)  { return blOrBTarget(at, instr, 0xea) }

// decodeMovImm reads the immediate back out of mov Rd,#imm (rot/value form).
// Doesn't handle movw; see decodeMovw.
func decodeMovImm(instr uint32, rd uint32) (uint32, bool) {
	if instr&0xfffff000 != 0xe3a00000|rd<<12 {
		return 0, false
	}
	rot := (instr >> 8) & 0xf
	v := instr & 0xff
	imm := v>>(2*rot) | v<<(32-2*rot)
	return imm, true
}

// decodeMovw reads the immediate back out of movw Rd,#imm.
func decodeMovw(instr uint32, rd uint32) (uint32, bool) {
	if instr&0xfff0f000 != 0xe3000000|rd<<12 {
		return 0, false
	}
	hi := (instr >> 16) & 0xf
	lo := instr & 0xfff
	return hi<<12 | lo, true
}
