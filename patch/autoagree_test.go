package patch

import (
	"testing"
)

func TestArmInstructionGenerators(t *testing.T) {
	// Test mov immediate
	m, err := mov(1, 73)
	if err != nil {
		t.Fatalf("mov(1, 73) failed: %v", err)
	}
	if m != 0xe3a01049 {
		t.Errorf("mov(1, 73) = %#x, want 0xe3a01049", m)
	}

	// Test movw valid
	mw, err := movw(1, 4892)
	if err != nil {
		t.Fatalf("movw(1, 4892) failed: %v", err)
	}
	if mw != 0xe301131c {
		t.Errorf("movw(1, 4892) = %#x, want 0xe301131c", mw)
	}

	// Test movw overflow (> 65535)
	if _, err := movw(1, 70000); err == nil {
		t.Error("expected error for movw with imm > 65535, got nil")
	}

	// Test ldrPC
	ldr, err := ldrPC(0x41a0a5c4, 2, 0x41a0a690)
	if err != nil {
		t.Fatalf("ldrPC failed: %v", err)
	}
	if ldr != 0xe59f20c4 {
		t.Errorf("ldrPC = %#x, want 0xe59f20c4", ldr)
	}
}

func TestPatchDelayLimits(t *testing.T) {
	b := Builds["G218ENNI.120"]
	m := make([]byte, b.ModLen)

	// Delay 0
	if _, err := PatchMod(m, b, ModeTimer, 0, nil); err == nil {
		t.Error("expected error for delay 0, got nil")
	}

	// Delay > 65535
	if _, err := PatchMod(m, b, ModeTimer, 70000, nil); err == nil {
		t.Error("expected error for delay 70000, got nil")
	}
}

func TestCorruptImageNoPanic(t *testing.T) {
	b := Builds["G218ENNI.120"]

	// Buffer too small
	if _, err := PatchMod([]byte{1, 2, 3}, b, ModeSkip, 2000, nil); err == nil {
		t.Error("expected error on small buffer, got nil")
	}

	// Buffer with corrupt chunk count
	corrupt := make([]byte, b.ModLen)
	corrupt[0x204] = 0xff
	corrupt[0x205] = 0xff
	if _, err := PatchMod(corrupt, b, ModeSkip, 2000, nil); err == nil {
		t.Error("expected error on corrupt chunk count, got nil")
	}
}
