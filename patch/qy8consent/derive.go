package qy8consent

import (
	"encoding/binary"
	"fmt"

	"LeafSDTools_Companion/patch/wince"
)

const imageScnCntCode = 0x20 // IMAGE_SCN_CNT_CODE; unexported in wince

// Derived is everything about one handler recovered from the image.
type Derived struct {
	CodeROM int
	CodeVA  uint32

	GetContext, SetVar, GetState, GetState2, EvHandler, ExecFn uint32
	SkipVA, Tail, PTrue                                        uint32
	VarSkip, VarAgree, VarStartup, Notify, Action              uint32
}

var stockMask = [29]uint32{
	0xff000000, 0xfffff000, 0xfffff000, 0xfffff000, 0xfffff000, 0xff000000, 0xff000000, 0xfffff000,
	0xfffff000, 0xff000000, 0xfffff000, 0xfff0f000, 0xfffff000, 0xff000000, 0xfffff000, 0xfffff000,
	0xffffffff, 0xffffffff, 0xff000000, 0xfffff000, 0xfffff000, 0xff000000, 0xfffff000, 0xfff0f000,
	0xfffff000, 0xff000000, 0xffffffff, 0xffffffff, 0xff000000,
}
var stockPattern = [29]uint32{
	0xeb000000, 0xe58d0000, 0xe59f2000, 0xe3a01000, 0xe59d0000, 0xeb000000, 0xeb000000, 0xe58d0000,
	0xe59d0000, 0xeb000000, 0xe58d0000, 0xe3001000, 0xe59d0000, 0xeb000000, 0xe58d0000, 0xe59d3000,
	0xe3530000, 0x1a000007, 0xeb000000, 0xe58d0000, 0xe59d0000, 0xeb000000, 0xe58d0000, 0xe3001000,
	0xe59d0000, 0xeb000000, 0xe3a03001, 0xe58d3000, 0xea000000,
}

// stockBLTargets maps each bl index in the stock handler to the function it calls.
var stockBLTargets = []struct {
	idx  int
	name string
}{
	{0, "getContext"}, {6, "getContext"}, {18, "getContext"},
	{5, "setVar"},
	{9, "getState"},
	{21, "getState2"},
	{13, "evHandler"}, {25, "evHandler"},
}

// patchedSig distinguishes "already patched" from "not found": the cmp/bne
// at +0x50 and mov/str at +0x68 never carry a build- or address-specific bit.
var patchedSig = [4]uint32{0xe3500000, 0x1a000003, 0xe3a03001, 0xe58d3000}
var patchedSigGaps = [4]int{0, 1, 6, 7} // word offsets from the first word

// derive locates the handler in seg0 and recovers everything in Derived.
// seg0 is segment 0's decompressed plaintext; rom is seg0||seg1 reconstructed.
func derive(seg0 []byte, rom []byte) (Derived, error) {
	ex, err := wince.NewExtractorAt(rom, 0)
	if err != nil {
		ex, err = wince.NewExtractor(rom)
		if err != nil {
			return Derived{}, fmt.Errorf("could not parse a WinCE ROM out of this nav image: %w", err)
		}
	}

	var scc *wince.Module
	for _, m := range ex.Modules {
		if m.Name == "ScreenStateCC.dll" {
			scc = m
		}
	}
	if scc == nil {
		return Derived{}, fmt.Errorf("ScreenStateCC.dll not found in the nav image's WinCE ROM")
	}
	var text *wince.O32Rom
	for i := range scc.O32s {
		if scc.O32s[i].Flags&imageScnCntCode != 0 {
			text = &scc.O32s[i]
			break
		}
	}
	if text == nil {
		return Derived{}, fmt.Errorf("ScreenStateCC.dll has no code section")
	}

	d := Derived{
		CodeVA:  scc.E32.VBase + text.RVA,
		CodeROM: int(text.DataPtr) - int(ex.LoadOffset),
	}
	if d.CodeROM < 0 || d.CodeROM+int(text.VSize) > len(seg0) {
		return Derived{}, fmt.Errorf("ScreenStateCC.dll's code section falls outside segment 0")
	}
	code := seg0[d.CodeROM : d.CodeROM+int(text.VSize)]

	sections, err := moduleSections(scc)
	if err != nil {
		return Derived{}, err
	}
	d.VarAgree, err = nameRank(sections, "VAR_I_AGREE_STATUS")
	if err != nil {
		return Derived{}, err
	}
	d.VarStartup, err = nameRank(sections, "VAR_START_UP_I_AGREE_STATUS")
	if err != nil {
		return Derived{}, err
	}
	d.Notify, err = nameRank(sections, "TELEMA_NOTIFY_AGREE")
	if err != nil {
		return Derived{}, err
	}
	varSkip, err := nameRank(sections, "VAR_CWS_AGREE_SKIP")
	if err != nil {
		return Derived{}, err
	}

	hit, pTrue, tail, err := findHandler(sections, code, d.CodeVA, varSkip)
	if err != nil {
		if findPatchedSig(code) {
			return Derived{}, fmt.Errorf("already patched")
		}
		return Derived{}, err
	}
	d.SkipVA = d.CodeVA + uint32(hit)
	d.PTrue = pTrue
	d.Tail = tail

	words := make([]uint32, 29)
	for i := range words {
		words[i] = binary.LittleEndian.Uint32(code[hit+i*4:])
	}

	targets := map[string]uint32{}
	for _, t := range stockBLTargets {
		tgt, ok := decodeBL(d.SkipVA+uint32(t.idx*4), words[t.idx])
		if !ok {
			return Derived{}, fmt.Errorf("stock[%d] is not a bl instruction", t.idx)
		}
		if prev, seen := targets[t.name]; seen && prev != tgt {
			return Derived{}, fmt.Errorf("%s decodes inconsistently (0x%08x vs 0x%08x)", t.name, prev, tgt)
		}
		targets[t.name] = tgt
	}
	d.GetContext, d.SetVar, d.GetState, d.GetState2, d.EvHandler = targets["getContext"], targets["setVar"], targets["getState"], targets["getState2"], targets["evHandler"]

	// execFn sits at getContext+0x50 in every build; the stock body never
	// calls it directly, so this is the only way to reach it.
	d.ExecFn = d.GetContext + 0x50

	decodedSkip, ok := decodeMovImm(words[3], 1)
	if !ok {
		return Derived{}, fmt.Errorf("stock[3] is not mov r1,#imm")
	}
	if decodedSkip != varSkip {
		return Derived{}, fmt.Errorf("VAR_CWS_AGREE_SKIP rank %d differs from handler value %d", varSkip, decodedSkip)
	}
	d.VarSkip = decodedSkip

	action1, ok1 := decodeMovw(words[11], 1)
	action2, ok2 := decodeMovw(words[23], 1)
	if !ok1 || !ok2 || action1 != action2 {
		return Derived{}, fmt.Errorf("action constant decodes inconsistently at stock[11]/[23]")
	}
	d.Action = action1

	return d, nil
}

// findMasked returns every offset where code's 29 words match pattern under mask.
func findMasked(code []byte, mask, pattern []uint32) []int {
	var hits []int
	n := len(mask)
	for p := 0; p+n*4 <= len(code); p += 4 {
		ok := true
		for i := 0; i < n; i++ {
			if binary.LittleEndian.Uint32(code[p+i*4:])&mask[i] != pattern[i] {
				ok = false
				break
			}
		}
		if ok {
			hits = append(hits, p)
		}
	}
	return hits
}

func findPatchedSig(code []byte) bool {
	for p := 0; p+28*4 <= len(code); p += 4 {
		match := true
		for i, gap := range patchedSigGaps {
			if binary.LittleEndian.Uint32(code[p+gap*4:]) != patchedSig[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func findHandler(sections []moduleSection, code []byte, codeVA, varSkip uint32) (int, uint32, uint32, error) {
	hits := findMasked(code, stockMask[:], stockPattern[:])
	var found []int
	var pTrue, tail uint32
	for _, skip := range hits {
		exec := skip + 0x84
		if exec+len(stockMask)*4 > len(code) || !maskedAt(code, exec, stockMask[:], stockPattern[:]) {
			continue
		}
		skipVar, ok1 := decodeMovImm(binary.LittleEndian.Uint32(code[skip+12:]), 1)
		execVar, ok2 := decodeMovImm(binary.LittleEndian.Uint32(code[exec+12:]), 1)
		if !ok1 || !ok2 || skipVar != execVar || skipVar != varSkip {
			continue
		}
		skipTail, ok1 := decodeB(codeVA+uint32(skip+28*4), binary.LittleEndian.Uint32(code[skip+28*4:]))
		execTail, ok2 := decodeB(codeVA+uint32(exec+28*4), binary.LittleEndian.Uint32(code[exec+28*4:]))
		if !ok1 || !ok2 || skipTail != execTail {
			continue
		}
		trueAt, trueText, ok1 := literalString(sections, code, codeVA, skip+8)
		_, falseText, ok2 := literalString(sections, code, codeVA, exec+8)
		if !ok1 || !ok2 || trueText != "true" || falseText != "false" {
			continue
		}
		found = append(found, exec)
		pTrue, tail = trueAt, execTail
	}
	if len(found) != 1 {
		return 0, 0, 0, fmt.Errorf("consent handler pair matched %d places, expected exactly 1", len(found))
	}
	return found[0], pTrue, tail, nil
}

func maskedAt(code []byte, at int, mask, pattern []uint32) bool {
	for i := range mask {
		if binary.LittleEndian.Uint32(code[at+i*4:])&mask[i] != pattern[i] {
			return false
		}
	}
	return true
}
