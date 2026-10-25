package patch

import (
	"os"
	"path/filepath"
	"reflect"
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

func mockBuildConfig() *BuildConfig {
	return &BuildConfig{
		Name:     "G218ENNI.120",
		ModLen:   31984640,
		Sec0File: 0xa7c000,
		Sec0VA:   0x413d1000,
		Skip: &SkipConfig{
			VA:    0x41a0a5c0,
			Stock: make([]uint32, 29),
		},
		Timer: &TimerConfig{
			VA:    0x419b8290,
			Stock: make([]uint32, 19),
		},
	}
}

func TestPatchDelayLimits(t *testing.T) {
	b := mockBuildConfig()
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
	b := mockBuildConfig()

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

// resolveImagePath шукає файл за відносними шляхами в робочому просторі.
func resolveImagePath(subpath string) string {
	candidates := []string{
		filepath.Join("..", subpath),
		filepath.Join("..", "..", subpath),
		subpath,
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.Size() > 0 {
			return c
		}
	}
	return ""
}

// TestLocateBuildsGolden перевіряє, що динамічно знайдені поля для G218ENNI.120 і G214ELNI.062
// повністю збігаються з еталонними значеннями таблиці PR #2 (включно з Stock: skip 29 слів, timer 19 слів).
func TestLocateBuildsGolden(t *testing.T) {
	// 1. Тест G218ENNI.120
	ze1Path := resolveImagePath("originals/qy8652nb/nand_20260827.bin")
	if ze1Path == "" {
		t.Skip("G218 image not found, skipping golden test")
	}

	ze1Data, err := os.ReadFile(ze1Path)
	if err != nil {
		t.Fatalf("failed to read ZE1 image: %v", err)
	}

	b218, err := LocateBuildConfig(ze1Data)
	if err != nil {
		t.Fatalf("LocateBuildConfig(ZE1) failed: %v", err)
	}

	if b218.Name != "G218ENNI.120" {
		t.Errorf("Name = %s, want G218ENNI.120", b218.Name)
	}
	if b218.ModLen != 31984640 {
		t.Errorf("ModLen = %d, want 31984640", b218.ModLen)
	}
	if b218.Sec0File != 0xa7c000 {
		t.Errorf("Sec0File = %#x, want 0xa7c000", b218.Sec0File)
	}
	if b218.Sec0VA != 0x413d1000 {
		t.Errorf("Sec0VA = %#x, want 0x413d1000", b218.Sec0VA)
	}
	if b218.GetContext != 0x41b2f560 || b218.SetVar != 0x41b2f3d0 || b218.CheckVar != 0x41b2f3e0 {
		t.Errorf("Thunks mismatch in G218: GetContext=%#x, SetVar=%#x, CheckVar=%#x", b218.GetContext, b218.SetVar, b218.CheckVar)
	}
	if b218.GetState != 0x41b2f430 || b218.GetState2 != 0x41b2f3f0 || b218.EvHandler != 0x41b2f640 || b218.ExecFn != 0x41b2f5b0 || b218.SetTimer != 0x41b2f650 {
		t.Errorf("Thunks mismatch in G218: GetState=%#x, ExecFn=%#x", b218.GetState, b218.ExecFn)
	}

	// SkipConfig G218
	if b218.Skip == nil {
		t.Fatal("SkipConfig is nil for G218")
	}
	if b218.Skip.VA != 0x41a0a5c0 || b218.Skip.Tail != 0x41a0a680 || b218.Skip.PTrue != 0x41a0a690 {
		t.Errorf("Skip addrs mismatch in G218: VA=%#x, Tail=%#x, PTrue=%#x", b218.Skip.VA, b218.Skip.Tail, b218.Skip.PTrue)
	}
	if b218.Skip.VarSkip != 73 || b218.Skip.VarAgree != 257 || b218.Skip.VarStartup != 628 {
		t.Errorf("Skip IDs mismatch in G218: VarSkip=%d, VarAgree=%d, VarStartup=%d", b218.Skip.VarSkip, b218.Skip.VarAgree, b218.Skip.VarStartup)
	}
	if b218.Skip.Action != 4892 || b218.Skip.Ctrl != 25 || b218.Skip.Notify != 1687 {
		t.Errorf("Skip params mismatch in G218: Action=%d, Ctrl=%d, Notify=%d", b218.Skip.Action, b218.Skip.Ctrl, b218.Skip.Notify)
	}
	if len(b218.Skip.Stock) != 29 {
		t.Errorf("Skip.Stock len = %d, want 29", len(b218.Skip.Stock))
	}
	goldenSkipStock218 := []uint32{
		0xeb0493e6, 0xe58d0134, 0xe59f20bc, 0xe3a01049, 0xe59d0134,
		0xeb04937d, 0xeb0493e0, 0xe58d0138, 0xe59d0138, 0xeb049391,
		0xe58d013c, 0xe301131c, 0xe59d013c, 0xeb049411, 0xe58d0140,
		0xe59d3140, 0xe3530000, 0x1a000007, 0xeb0493d4, 0xe58d0144,
		0xe59d0144, 0xeb049375, 0xe58d0148, 0xe301131c, 0xe59d0148,
		0xeb049405, 0xe3a03001, 0xe58d3000, 0xea000012,
	}
	if !reflect.DeepEqual(b218.Skip.Stock, goldenSkipStock218) {
		t.Errorf("Skip.Stock words mismatch for G218")
	}

	// TimerConfig G218
	if b218.Timer == nil {
		t.Fatal("TimerConfig is nil for G218")
	}
	if b218.Timer.VA != 0x419b8290 || b218.Timer.Tail != 0x419bb13c || b218.Timer.PTrue != 0x419b91c8 || b218.Timer.PFalse != 0x419b91cc {
		t.Errorf("Timer addrs mismatch in G218: VA=%#x, Tail=%#x", b218.Timer.VA, b218.Timer.Tail)
	}
	if b218.Timer.VarStartup != 628 || b218.Timer.Event != 0xc93 {
		t.Errorf("Timer params mismatch in G218: VarStartup=%d, Event=%#x", b218.Timer.VarStartup, b218.Timer.Event)
	}
	if len(b218.Timer.Stock) != 19 {
		t.Errorf("Timer.Stock len = %d, want 19", len(b218.Timer.Stock))
	}
	goldenTimerStock218 := []uint32{
		0xeb05dcb2, 0xe58d0004, 0xe59f2f2c, 0xe3a01f9d, 0xe59d0004,
		0xeb05dc4d, 0xe58d0008, 0xe59d3008, 0xe3530000, 0x0a000005,
		0xeb05dca8, 0xe58d000c, 0xe59f2f00, 0xe3a01f9d, 0xe59d000c,
		0xeb05dc3f, 0xe3a03001, 0xe58d3000, 0xea000b97,
	}
	if !reflect.DeepEqual(b218.Timer.Stock, goldenTimerStock218) {
		t.Errorf("Timer.Stock words mismatch for G218")
	}

	// 2. Тест G214ELNI.062
	ze0Path := resolveImagePath("originals/qy8202na/nand_ze0_qy8202na_g214.bin")
	if ze0Path == "" {
		t.Skip("G214 image not found, skipping golden test")
	}

	ze0Data, err := os.ReadFile(ze0Path)
	if err != nil {
		t.Fatalf("failed to read ZE0 image: %v", err)
	}

	b214, err := LocateBuildConfig(ze0Data)
	if err != nil {
		t.Fatalf("LocateBuildConfig(ZE0) failed: %v", err)
	}

	if b214.Name != "G214ELNI.062" {
		t.Errorf("Name = %s, want G214ELNI.062", b214.Name)
	}
	if b214.ModLen != 30647808 {
		t.Errorf("ModLen = %d, want 30647808", b214.ModLen)
	}
	if b214.Sec0File != 0xa11000 {
		t.Errorf("Sec0File = %#x, want 0xa11000", b214.Sec0File)
	}
	if b214.Sec0VA != 0x412e1000 {
		t.Errorf("Sec0VA = %#x, want 0x412e1000", b214.Sec0VA)
	}
	if b214.GetContext != 0x419d376c || b214.SetVar != 0x419d35dc || b214.CheckVar != 0x419d35ec {
		t.Errorf("Thunks mismatch in G214: GetContext=%#x, SetVar=%#x, CheckVar=%#x", b214.GetContext, b214.SetVar, b214.CheckVar)
	}
	if b214.GetState != 0x419d363c || b214.GetState2 != 0x419d35fc || b214.EvHandler != 0x419d384c || b214.ExecFn != 0x419d37bc || b214.SetTimer != 0x419d385c {
		t.Errorf("Thunks mismatch in G214: GetState=%#x, ExecFn=%#x", b214.GetState, b214.ExecFn)
	}

	// SkipConfig G214
	if b214.Skip == nil {
		t.Fatal("SkipConfig is nil for G214")
	}
	if b214.Skip.VA != 0x418b6488 || b214.Skip.Tail != 0x418b6530 || b214.Skip.PTrue != 0x418b6540 {
		t.Errorf("Skip addrs mismatch in G214: VA=%#x, Tail=%#x, PTrue=%#x", b214.Skip.VA, b214.Skip.Tail, b214.Skip.PTrue)
	}
	if b214.Skip.VarSkip != 47 || b214.Skip.VarAgree != 223 || b214.Skip.VarStartup != 563 {
		t.Errorf("Skip IDs mismatch in G214: VarSkip=%d, VarAgree=%d, VarStartup=%d", b214.Skip.VarSkip, b214.Skip.VarAgree, b214.Skip.VarStartup)
	}
	if b214.Skip.Action != 4676 || b214.Skip.Ctrl != 25 || b214.Skip.Notify != 1609 {
		t.Errorf("Skip params mismatch in G214: Action=%d, Ctrl=%d, Notify=%d", b214.Skip.Action, b214.Skip.Ctrl, b214.Skip.Notify)
	}
	if len(b214.Skip.Stock) != 29 {
		t.Errorf("Skip.Stock len = %d, want 29", len(b214.Skip.Stock))
	}
	goldenSkipStock214 := []uint32{
		0xeb0474b7, 0xe58d00d4, 0xe59f20a4, 0xe3a0102f, 0xe59d00d4,
		0xeb04744e, 0xeb0474b1, 0xe58d00d8, 0xe59d00d8, 0xeb047462,
		0xe58d00dc, 0xe3011244, 0xe59d00dc, 0xeb0474e2, 0xe58d00e0,
		0xe59d30e0, 0xe3530000, 0x1a000007, 0xeb0474a5, 0xe58d00e4,
		0xe59d00e4, 0xeb047446, 0xe58d00e8, 0xe3011244, 0xe59d00e8,
		0xeb0474d6, 0xe3a03001, 0xe58d3000, 0xea00000c,
	}
	if !reflect.DeepEqual(b214.Skip.Stock, goldenSkipStock214) {
		t.Errorf("Skip.Stock words mismatch for G214")
	}

	// TimerConfig G214 (знайдено динамічно)
	if b214.Timer == nil {
		t.Fatal("TimerConfig is nil for G214")
	}
	if b214.Timer.VA != 0x41868570 || b214.Timer.Tail != 0x4186b1dc || b214.Timer.PTrue != 0x41869294 || b214.Timer.PFalse != 0x41869298 {
		t.Errorf("Timer addrs mismatch in G214: VA=%#x, Tail=%#x", b214.Timer.VA, b214.Timer.Tail)
	}
	if b214.Timer.VarStartup != 563 || b214.Timer.Event != 0xc2f {
		t.Errorf("Timer params mismatch in G214: VarStartup=%d, Event=%#x (want 0xc2f)", b214.Timer.VarStartup, b214.Timer.Event)
	}
	if len(b214.Timer.Stock) != 19 {
		t.Errorf("Timer.Stock len = %d, want 19", len(b214.Timer.Stock))
	}
}
