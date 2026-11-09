// Diagnostic tooling for the QY8 consent patch: reports what the patcher
// looks for and what the image actually contains. Investigation aid, not part
// of the patch flow.
package qy8consent

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"LeafSDTools_Companion/patch/wince"
)

type Diag struct {
	Out        io.Writer
	Tgt        Target
	Mod        []byte
	Seg0       []byte
	Chunk      []chunk
	Plain      [][]byte
	Rom        []byte
	LoadOffset int64
	Ex         *wince.Extractor
	Scc        *wince.Module
}

func (d *Diag) printf(f string, a ...any) { fmt.Fprintf(d.Out, f, a...) }

// Load opens a card image (or a raw .mod container) and unpacks its segments.
func Load(path string, out io.Writer) (*Diag, error) {
	d := &Diag{Out: out}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("not a file")
	}

	if st.Size() > 0x20000 {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		t, err := Find(f, st.Size())
		if err != nil {
			return nil, fmt.Errorf("Find: %w", err)
		}
		d.Tgt = t
		d.printf("nav image: name=%q offset=0x%x size=%d\n", t.Build, t.Offset, t.Size)
		mod := make([]byte, t.Size)
		if _, err := f.ReadAt(mod, t.Offset); err != nil && err != io.EOF {
			return nil, err
		}
		d.Mod = mod
	} else {
		mod, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		name, err := readName(mod[:min(int(offSegTable), len(mod))])
		if err != nil {
			return nil, err
		}
		d.Mod = mod
		d.Tgt = Target{Offset: 0, Build: name, Size: len(mod)}
		d.printf("container file: name=%q size=%d\n", name, len(mod))
	}

	cs, err := chunks(d.Mod)
	if err != nil {
		return nil, fmt.Errorf("segment 0: %w", err)
	}
	d.Chunk = cs
	d.printf("segment 0: table=0x%x chunks=%d\n", segOffset, len(cs))
	for i, c := range cs {
		d.printf("  [%2d] at=0x%-8x sectors=%-6d plain=%-9d packed=%-9d sum=%08x\n",
			i, c.at, c.sectors, c.plain, c.packed, binary.LittleEndian.Uint32(d.Mod[c.tableEnt+12:]))
	}
	d.Sums(d.Mod, cs)

	seg0, plains, err := decompressAll(d.Mod, cs)
	if err != nil {
		return nil, fmt.Errorf("segment 0: %w", err)
	}
	d.Seg0, d.Plain = seg0, plains
	more, segEnd, err := nextSegments(d.Mod, cs)
	if err != nil {
		return nil, err
	}
	d.printf("further segments: %d bytes, container consumed to 0x%x of 0x%x\n", len(more), segEnd, len(d.Mod))
	rom := make([]byte, 0, len(seg0)+len(more)+len(d.Mod)-segEnd)
	rom = append(rom, seg0...)
	rom = append(rom, more...)
	rom = append(rom, d.Mod[segEnd:]...)
	d.Rom = rom
	d.printf("seg0=%d bytes, rom=%d bytes\n", len(seg0), len(rom))

	ex, err := wince.NewExtractorAt(rom, 0)
	if err != nil {
		ex, err = wince.NewExtractor(rom)
		if err != nil {
			d.printf("no WinCE ROM found: %v\n", err)
			return d, fmt.Errorf("no WinCE ROM in image: %w", err)
		}
	}
	d.Ex = ex
	d.LoadOffset = ex.LoadOffset
	d.printf("modules: %d files: %d\n", len(ex.Modules), len(ex.Files))
	for _, m := range ex.Modules {
		if m.Name == "ScreenStateCC.dll" {
			d.Scc = m
		}
	}
	if d.Scc == nil {
		return d, fmt.Errorf("ScreenStateCC.dll not found")
	}
	return d, nil
}

// Sums prints which byte ranges of the container add up to the checksums the
// headers claim, so the loader's real span can be pinned down.
func (d *Diag) Sums(mod []byte, cs []chunk) {
	segLen := binary.LittleEndian.Uint32(mod[offSegTable+8:])
	segSum := binary.LittleEndian.Uint32(mod[offSegTable+12:])
	segEnd := segOffset + int(segLen)
	d.printf("segment0 from the table: len=0x%x sum=0x%08x\n", segLen, segSum)
	d.printf("  SUM4@0x34=0x%08x  wordSum(mod[0x200:])=0x%08x match=%v\n",
		binary.LittleEndian.Uint32(mod[offSum4:]), wordSum(mod[segOffset:]),
		binary.LittleEndian.Uint32(mod[offSum4:]) == wordSum(mod[segOffset:]))
	if segEnd <= len(mod) {
		d.printf("  wordSum(0x200..0x%x)=0x%08x match=%v\n", segEnd, wordSum(mod[segOffset:segEnd]),
			wordSum(mod[segOffset:segEnd]) == segSum)
	}
	d.printf("  loaderSum(metadata sector + chunks)=0x%08x match=%v\n", loaderSum(mod, cs),
		loaderSum(mod, cs) == segSum)
	d.printf("  per-chunk sums ok: %v\n", chunkSumsOK(mod, cs))
	d.printf("  reserved word @0x%x = % x\n", segOffset+offReserved, mod[segOffset+offReserved:segOffset+offReserved+4])
}

func (d *Diag) CodeSection() ([]byte, uint32, int, error) {
	var text *wince.O32Rom
	for i := range d.Scc.O32s {
		if d.Scc.O32s[i].Flags&imageScnCntCode != 0 {
			text = &d.Scc.O32s[i]
			break
		}
	}
	if text == nil {
		return nil, 0, 0, fmt.Errorf("no code section")
	}
	codeVA := d.Scc.E32.VBase + text.RVA
	romOff := int(text.DataPtr) - int(d.Ex.LoadOffset)
	if romOff < 0 || romOff+int(text.VSize) > len(d.Seg0) {
		return nil, 0, 0, fmt.Errorf("code section outside segment 0 (off=0x%x size=0x%x seg0=0x%x)",
			romOff, text.VSize, len(d.Seg0))
	}
	return d.Seg0[romOff : romOff+int(text.VSize)], codeVA, romOff, nil
}

// Sections prints the module's PE sections.
func (d *Diag) Sections() {
	img, err := d.Scc.Image()
	if err != nil {
		d.printf("module image: %v\n", err)
		return
	}
	pe := int(binary.LittleEndian.Uint32(img[0x3c:]))
	count := int(binary.LittleEndian.Uint16(img[pe+6:]))
	optSize := int(binary.LittleEndian.Uint16(img[pe+20:]))
	table := pe + 24 + optSize
	d.printf("ScreenStateCC.dll: vbase=0x%08x sections=%d\n", d.Scc.E32.VBase, count)
	for i := 0; i < count && i < len(d.Scc.O32s); i++ {
		h := img[table+i*40:]
		name := strings.TrimRight(string(h[0:8]), "\x00")
		va := d.Scc.E32.VBase + binary.LittleEndian.Uint32(h[12:])
		d.printf("  %-8s va=0x%08x vsize=0x%-8x raw=0x%-8x\n", name, va,
			binary.LittleEndian.Uint32(h[8:]), binary.LittleEndian.Uint32(h[16:]))
	}
}

// Names lists interesting identifiers present in ScreenStateCC.dll with their
// derived rank, i.e. the value the state machine uses for them.
func (d *Diag) Names(keywords ...string) {
	sections, err := moduleSections(d.Scc)
	if err != nil {
		d.printf("moduleSections: %v\n", err)
		return
	}
	set := map[string]bool{}
	for _, s := range sections {
		for _, str := range extractStrings(s.data, 4) {
			for _, kw := range keywords {
				if strings.Contains(strings.ToUpper(str), strings.ToUpper(kw)) {
					set[str] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	d.printf("interesting strings (%d):\n", len(out))
	for _, s := range out {
		rank, err := nameRank(sections, s)
		if err != nil {
			d.printf("  %-44s rank=-\n", s)
			continue
		}
		d.printf("  %-44s rank=%d\n", s, rank)
	}
}

func extractStrings(b []byte, minLen int) []string {
	var out []string
	start := -1
	for i := 0; i <= len(b); i++ {
		ok := i < len(b) && b[i] >= 0x20 && b[i] < 0x7f
		if ok {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= minLen {
			out = append(out, string(b[start:i]))
		}
		start = -1
	}
	return out
}

// Handler reports where the stock handler pattern matches and why each match
// is accepted or rejected by findHandler's checks.
func (d *Diag) Handler(varSkip uint32) {
	code, codeVA, romOff, err := d.CodeSection()
	if err != nil {
		d.printf("CodeSection: %v\n", err)
		return
	}
	d.printf("code: len=0x%x va=0x%x romOff=0x%x\n", len(code), codeVA, romOff)
	hits := findMasked(code, stockMask[:], stockPattern[:])
	d.printf("masked pattern hits: %d\n", len(hits))
	d.printf("already-patched signature: %v\n", findPatchedSig(code))

	sections, err := moduleSections(d.Scc)
	if err != nil {
		d.printf("moduleSections: %v\n", err)
		return
	}
	for _, skip := range hits {
		exec := skip + 0x84
		if exec+len(stockMask)*4 > len(code) || !maskedAt(code, exec, stockMask[:], stockPattern[:]) {
			continue
		}
		skipVar, ok1 := decodeMovImm(binary.LittleEndian.Uint32(code[skip+12:]), 1)
		execVar, ok2 := decodeMovImm(binary.LittleEndian.Uint32(code[exec+12:]), 1)
		skipTail, ok3 := decodeB(codeVA+uint32(skip+28*4), binary.LittleEndian.Uint32(code[skip+28*4:]))
		execTail, ok4 := decodeB(codeVA+uint32(exec+28*4), binary.LittleEndian.Uint32(code[exec+28*4:]))
		trueAt, trueText, ok5 := literalString(sections, code, codeVA, skip+8)
		_, falseText, ok6 := literalString(sections, code, codeVA, exec+8)
		d.printf("pair skip=0x%08x exec=0x%08x: skipVar=%d,%v execVar=%d,%v (want %d) tails=%v,%v,%v true=%q@0x%x(%v) false=%q(%v)\n",
			codeVA+uint32(skip), codeVA+uint32(exec), skipVar, ok1, execVar, ok2, varSkip, ok3, ok4, skipTail == execTail,
			trueText, trueAt, ok5, falseText, ok6)
		if ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && skipVar == varSkip && execVar == varSkip && skipTail == execTail && trueText == "true" && falseText == "false" {
			d.printf("  -> this pair is the consent handler\n")
		}
	}
	d.printf("findHandler: ")
	_, _, _, err = findHandler(sections, code, codeVA, varSkip)
	d.printf("%v\n", err)
}

// Ranks checks the four names the patcher requires.
func (d *Diag) Ranks() uint32 {
	sections, err := moduleSections(d.Scc)
	if err != nil {
		d.printf("moduleSections: %v\n", err)
		return 0
	}
	var skip uint32
	for _, n := range []string{"VAR_I_AGREE_STATUS", "VAR_START_UP_I_AGREE_STATUS", "TELEMA_NOTIFY_AGREE", "VAR_CWS_AGREE_SKIP"} {
		r, err := nameRank(sections, n)
		if err != nil {
			d.printf("  %-30s -> error: %v\n", n, err)
			continue
		}
		d.printf("  %-30s -> rank %d\n", n, r)
		if n == "VAR_CWS_AGREE_SKIP" {
			skip = r
		}
	}
	return skip
}

// Dump writes the reconstructed rom and ScreenStateCC.dll image for offline
// disassembly.
func (d *Diag) Dump(dir string) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		d.printf("mkdir: %v\n", err)
		return
	}
	os.WriteFile(dir+"/rom.bin", d.Rom, 0o644)
	if len(d.Mod) > 0 {
		os.WriteFile(dir+"/nav.mod", d.Mod, 0o644)
	}
	if d.Scc != nil {
		if img, err := d.Scc.Image(); err == nil {
			os.WriteFile(dir+"/ScreenStateCC.dll", img, 0o644)
			d.printf("wrote rom.bin, nav.mod and ScreenStateCC.dll to %s\n", dir)
		} else {
			d.printf("module image: %v\n", err)
		}
	}
}

// FullDerive runs derive() and prints the result, useful to compare against a
// known-good card.
func (d *Diag) FullDerive() {
	dd, err := derive(d.Seg0, d.Rom)
	if err != nil {
		d.printf("derive: %v\n", err)
		return
	}
	d.printf("derive ok: skip=0x%08x code=0x%08x rom=0x%x ctx=0x%08x setVar=0x%08x state=0x%08x state2=0x%08x ev=0x%08x exec=0x%08x tail=0x%08x pTrue=0x%08x varSkip=%d varAgree=%d varStartup=%d notify=%d action=%d\n",
		dd.SkipVA, dd.CodeVA, dd.CodeROM, dd.GetContext, dd.SetVar, dd.GetState, dd.GetState2, dd.EvHandler, dd.ExecFn, dd.Tail, dd.PTrue,
		dd.VarSkip, dd.VarAgree, dd.VarStartup, dd.Notify, dd.Action)
}

// Plan runs the whole patch pipeline without writing anything: it reports the
// page writes the patch would make and the checksums it had to keep.
func Plan(f io.ReaderAt, size int64, log func(string)) (Result, []PageWrite, error) {
	return planConsentSkip(f, size, log)
}

// TryPatch runs the real patcher on an in-memory copy and prints the checksum
// bookkeeping, which is what the loader will verify.
func (d *Diag) TryPatch() {
	before := bytes.Clone(d.Mod)
	res, err := patchMod(before, d.Tgt.Build, func(s string) { d.printf("  patch: %s\n", s) })
	if err != nil {
		d.printf("patchMod: %v\n", err)
	} else {
		d.printf("patchMod ok: chunk=%d %d->%d bytes, drift=0x%08x pages=%d\n",
			res.Chunk, res.Stock, res.Packed, res.Compensation, res.Pages)
	}
	cs, _ := chunks(before)
	segLen := int(binary.LittleEndian.Uint32(before[offSegTable+8:]))
	segSum := binary.LittleEndian.Uint32(before[offSegTable+12:])
	segEnd := segOffset + segLen
	lastEnd := cs[len(cs)-1].at + cs[len(cs)-1].sectors*sectorSize
	d.printf("after patch: segEnd=0x%x lastChunkEnd=0x%x segSum=0x%08x\n", segEnd, lastEnd, segSum)
	d.printf("  wordSum(0x200..segEnd) = 0x%08x match=%v\n", wordSum(before[segOffset:segEnd]),
		wordSum(before[segOffset:segEnd]) == segSum)
	d.printf("  loaderSum              = 0x%08x match=%v\n", loaderSum(before, cs),
		loaderSum(before, cs) == segSum)
	d.printf("  sum(metadata sector)   = 0x%08x\n", wordSum(before[segOffset:segOffset+sectorSize]))
	var rooms uint32
	for _, c := range cs {
		rooms += wordSum(before[c.at : c.at+c.sectors*sectorSize])
	}
	d.printf("  sum(chunk rooms)       = 0x%08x\n", rooms)
	d.printf("  SUM4@0x34=0x%08x wordSum(after header)=0x%08x match=%v\n",
		binary.LittleEndian.Uint32(before[offSum4:]), wordSum(before[segOffset:]),
		binary.LittleEndian.Uint32(before[offSum4:]) == wordSum(before[segOffset:]))
}

// Words prints the stock and the patched instruction words at the handler,
// which is what a running guest can be checked against.
func (d *Diag) Words() {
	dd, err := derive(d.Seg0, d.Rom)
	if err != nil {
		d.printf("derive: %v\n", err)
		return
	}
	code, _, _, err := d.CodeSection()
	if err != nil {
		d.printf("CodeSection: %v\n", err)
		return
	}
	at := int(dd.SkipVA - dd.CodeVA)
	d.printf("stock words at 0x%08x:\n", dd.SkipVA)
	for i := 0; i < 29; i += 4 {
		var line []string
		for j := i; j < min(i+4, 29); j++ {
			line = append(line, fmt.Sprintf("%08x", binary.LittleEndian.Uint32(code[at+j*4:])))
		}
		d.printf("  +0x%02x  %s\n", i*4, strings.Join(line, " "))
	}
	d.printf("patched words at 0x%08x:\n", dd.SkipVA)
	body := skipBody(dd)
	for i := 0; i < len(body); i += 4 {
		var line []string
		for j := i; j < min(i+4, len(body)); j++ {
			line = append(line, fmt.Sprintf("%08x", body[j]))
		}
		d.printf("  +0x%02x  %s\n", i*4, strings.Join(line, " "))
	}
}

var _ = bytes.Equal
