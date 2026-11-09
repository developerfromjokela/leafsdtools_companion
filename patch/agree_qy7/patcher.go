package agree_qy7

import (
	"LeafSDTools_Companion/patch/wince"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
)

const (
	ciOffAlloc            = 0x0c // mov.l @(disp,PC),r3  -> allocator
	ciOffBase             = 0x1c // mov.l @(disp,PC),r0  -> InitState
	ciOffVtbl             = 0x24 // mov.l @(disp,PC),r2  -> vtable
	ciOffSize             = 0x10 // mov #size,r4
	vtEventListenerOffset = 21
	vtInit1Offset         = 16
	vtInit2Offset         = 18
)

var scrStateDebugSigBytes = []byte{
	0xe6, 0x2f, // mov.l r14,@-r15
	0x86, 0x2f, // mov.l r8,@-r15
	0x96, 0x2f, // mov.l r9,@-r15
	0xa6, 0x2f, // mov.l r10,@-r15
	0xb6, 0x2f, // mov.l r11,@-r15
	0x22, 0x4f, // sts.l PR,@-r15
	0xf3, 0x6e, // mov r15,r14
	0xe8, 0x7f, // add #-0x18,r15
	0x73, 0x6b, // mov r7,r11
	0x63, 0x6a, // mov r6,r10
	0x53, 0x63, // mov r5,r3
	0x00, 0x92, // mov.w @(disp,PC),r2   <- disp wildcarded
	0xff, 0x73, // add #-1,r3
	0x26, 0x33, // cmp/hi r2,r3
	0x3e, 0x89, // bt LAB_...
	0x00, 0xd2, // mov.l @(disp,PC),r2   <- disp wildcarded
}

var scrStateDebugSigMask = []byte{
	1, 1,
	1, 1,
	1, 1,
	1, 1,
	1, 1,
	1, 1,
	1, 1,
	1, 1,
	1, 1,
	1, 1,
	1, 1,
	0, 1,
	1, 1,
	1, 1,
	1, 1,
	0, 1,
}

var otherStatesSigBytes = []byte{
	0xe6, 0x2f, // mov.l r14,@-r15
	0x86, 0x2f, // mov.l r8,@-r15
	0x96, 0x2f, // mov.l r9,@-r15
	0xa6, 0x2f, // mov.l r10,@-r15
	0xb6, 0x2f, // mov.l r11,@-r15
	0x22, 0x4f, // sts.l PR,@-r15
	0xf3, 0x6e, // mov r15,r14
	0xe8, 0x7f, // add #-0x18,r15
	0x73, 0x6b, // mov r7,r11
	0x63, 0x6a, // mov r6,r10
	0x53, 0x63, // mov r5,r3
	0x00, 0x92, // mov.w @(disp,PC),r2   <- disp wildcarded (count literal)
	0xfd, 0x73, // add #-3,r3            <- first valid index = 3
	0x26, 0x33, // cmp/hi r2,r3
	0x00, 0x89, // bt LAB_...            <- disp wildcarded
	0x00, 0xd2, // mov.l @(disp,PC),r2   <- disp wildcarded (pointer literal)
}

var otherStatesSigMask = []byte{
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	0, 1, // mov.w
	1, 1, // add #-3,r3
	1, 1, // cmp/hi
	0, 1, // bt
	0, 1, // mov.l
}

func findSig(buf, sig, mask []byte) int {
	n := len(sig)
	for i := 0; i+n <= len(buf); i++ {
		ok := true
		for j := 0; j < n; j++ {
			if mask[j] == 1 && buf[i+j] != sig[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

// findInSection Finds a pattern inside section data and returns real address and offset in data
func findInSection(section *wince.Section, pattern []byte) (uint32, uint32) {
	for from := 0; from < len(section.Data); {
		i := bytes.Index(section.Data[from:], pattern)
		if i < 0 {
			break
		}
		return section.RealAddr + uint32(from+i), uint32(from + i)
	}
	return 0, 0
}

// State Class Finder

type ClassInitializer struct {
	FuncVA         uint32 // address of the initializer function
	Size           int    // object size passed to the allocator (mov #size,r4)
	AllocVA        uint32 // allocator (operator new) it calls
	BaseInitVA     uint32 // base-class init called on the new object (InitState)
	VtableVA       uint32 // vtable stored into the object
	VtableContent  []uint32
	GetMainStateVA uint32 // vtable[1]
	ID             uint16 // constant returned by vtable[1]
	HasID          bool   // false if vtable[1] was not a "mov.w #ID,r0; rts; nop" getter
}

func classInitSignature(size byte) (sig, mask []byte) {
	fixed := func(bs ...byte) {
		for _, v := range bs {
			sig = append(sig, v)
			mask = append(mask, 0xff)
		}
	}
	// low byte wildcarded, high byte compared under hiMask
	wild := func(hi, hiMask byte) {
		sig = append(sig, 0, hi)
		mask = append(mask, 0x00, hiMask)
	}

	fixed(0xe6, 0x2f, 0x86, 0x2f, 0x22, 0x4f, 0xf3, 0x6e, 0xfc, 0x7e, 0xec, 0x7f) // prolog
	wild(0xd3, 0xff)                                                              // +0x0c mov.l @(disp,PC),r3
	fixed(0x0b, 0x43)                                                             // jsr @r3
	if size == 0 {                                                                // +0x10 mov #size,r4
		sig = append(sig, 0, 0xe4)
		mask = append(mask, 0x00, 0xff)
	} else {
		fixed(size, 0xe4)
	}
	fixed(0x03, 0x62, 0x03, 0x68, 0x22, 0x2e, 0x88, 0x28) // mov r0,r2; mov r0,r8; mov.l r2,@r14; tst r8,r8
	wild(0x89, 0xff)                                      // bt
	wild(0xd0, 0xff)                                      // +0x1c mov.l @(disp,PC),r0 (InitState)
	fixed(0x83, 0x64, 0x0b, 0x40, 0x09, 0x00)             // mov r8,r4; jsr @r0; nop
	wild(0xd2, 0xff)                                      // +0x24 mov.l @(disp,PC),r2 (vtable)
	wild(0xa0, 0xf0)                                      // bra (disp12)
	fixed(0x22, 0x28)                                     // mov.l r2,@r8  (delay slot)
	return sig, mask
}

func matchMasked(buf, sig, mask []byte) bool {
	for j := range sig {
		if buf[j]&mask[j] != sig[j]&mask[j] {
			return false
		}
	}
	return true
}

func readVA(secs []wince.Section, va uint32, n int) ([]byte, bool) {
	for i := range secs {
		s := &secs[i]
		if va >= s.RealAddr && uint64(va)+uint64(n) <= uint64(s.RealAddr)+uint64(len(s.Data)) {
			off := va - s.RealAddr
			return s.Data[off : off+uint32(n)], true
		}
	}
	return nil, false
}

func readConstGetter(secs []wince.Section, va uint32) (uint16, bool) {
	code, ok := readVA(secs, va, 6)
	if !ok {
		return 0, false
	}
	w0 := binary.LittleEndian.Uint16(code[0:])
	w1 := binary.LittleEndian.Uint16(code[2:])
	w2 := binary.LittleEndian.Uint16(code[4:])
	if w0&0xFF00 != 0x9000 || w1 != 0x000b || w2 != 0x0009 {
		return 0, false
	}
	litVA := va + 4 + uint32(w0&0xFF)*2
	b, ok := readVA(secs, litVA, 2)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b), true
}

func decodeClassInit(secs []wince.Section, text wince.Section, fn int, vtableAddrCount int) (ClassInitializer, error) {
	buf := text.Data
	lit := func(off int) (uint32, error) {
		t, err := movlPCRelTarget(buf, fn+off)
		if err != nil {
			return 0, err
		}
		if t < 0 || t+4 > len(buf) {
			return 0, errors.New("literal out of range")
		}
		return binary.LittleEndian.Uint32(buf[t:]), nil
	}

	c := ClassInitializer{
		FuncVA:        text.RealAddr + uint32(fn),
		Size:          int(buf[fn+ciOffSize]),
		VtableContent: make([]uint32, vtableAddrCount),
	}
	var err error
	if c.AllocVA, err = lit(ciOffAlloc); err != nil {
		return c, err
	}
	if c.BaseInitVA, err = lit(ciOffBase); err != nil {
		return c, err
	}
	if c.VtableVA, err = lit(ciOffVtbl); err != nil {
		return c, err
	}

	for i := 0; i < vtableAddrCount; i++ {
		vt, ok := readVA(secs, c.VtableVA+uint32(i*4), 4)
		if !ok {
			c.VtableContent[i] = 0
			continue
		}
		c.VtableContent[i] = binary.LittleEndian.Uint32(vt)
	}

	vt, ok := readVA(secs, c.VtableVA+4, 4) // vtable[1]
	if !ok {
		return c, errors.New("vtable not readable")
	}
	c.GetMainStateVA = binary.LittleEndian.Uint32(vt)
	c.ID, c.HasID = readConstGetter(secs, c.GetMainStateVA)
	return c, nil
}

func FindClassInitializers(secs []wince.Section, size int, vtableAddrCount int) ([]ClassInitializer, error) {
	if size < 0 || size > 0x7f {
		return nil, fmt.Errorf("%#x not encodable for mov #imm,r4", size)
	}
	var text *wince.Section = nil
	for _, sec := range secs {
		if sec.Name == ".text" {
			text = &sec
			break
		}
	}

	if text == nil {
		return nil, fmt.Errorf("no .text section")
	}

	sig, mask := classInitSignature(byte(size))

	var out []ClassInitializer
	for i := 0; i+len(sig) <= len((*text).Data); i += 2 { // SH instructions are 2-byte aligned
		if !matchMasked(text.Data[i:], sig, mask) {
			continue
		}
		if c, err := decodeClassInit(secs, *text, i, vtableAddrCount); err == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

// Screen State Table Finder

func movwPCRelTarget(buf []byte, instrOff int) (int, error) {
	if instrOff < 0 || instrOff+2 > len(buf) {
		return 0, errors.New("mov.w: offset out of range")
	}
	word := binary.LittleEndian.Uint16(buf[instrOff:])
	if word&0xF000 != 0x9000 {
		return 0, fmt.Errorf("not mov.w @(disp,PC) at off %#x (word=%#04x)", instrOff, word)
	}
	disp := int(word & 0x00FF)
	return instrOff + 4 + disp*2, nil
}

func movlPCRelTarget(buf []byte, instrOff int) (int, error) {
	if instrOff < 0 || instrOff+2 > len(buf) {
		return 0, errors.New("mov.l: offset out of range")
	}
	word := binary.LittleEndian.Uint16(buf[instrOff:])
	if word&0xF000 != 0xD000 {
		return 0, fmt.Errorf("not mov.l @(disp,PC) at off %#x (word=%#04x)", instrOff, word)
	}
	disp := int(word & 0x00FF)
	return ((instrOff + 4) &^ 3) + disp*4, nil
}

func cStringAt(data []byte, off uint32) (string, bool) {
	if int64(off) >= int64(len(data)) {
		return "", false
	}
	s, _, found := bytes.Cut(data[off:], []byte{0})
	return string(s), found
}

type ScreenStateDebuggerAnalysisResult struct {
	DatVal   uint16 // Total states count
	PtrTable uint32 // Raw address value of state labels
	DatArray uint32 // Actual starting address (subtracted by 4, since list starts at 0)
}

type OtherStatesAnalysisResult struct {
	DatVal     uint16 // value of the mov.w literal: highest valid (index - FirstIndex)
	PtrTable   uint32 // raw mov.l literal = address of the first item (index FirstIndex)
	DatArray   uint32 // address of virtual item 0 (PtrTable - 4*FirstIndex)
	FirstIndex uint32 // first valid index (3)
	Count      uint32 // number of items (DatVal+1)
}

func ScreenStateDebuggerAnalysis(buf []byte) (*ScreenStateDebuggerAnalysisResult, error) {
	fnOff := findSig(buf, scrStateDebugSigBytes, scrStateDebugSigMask)
	if fnOff == -1 {
		return nil, errors.New("signature not found")
	}

	movwOff := fnOff + 22
	datOff, err := movwPCRelTarget(buf, movwOff)
	if err != nil {
		return nil, err
	}
	if datOff+2 > len(buf) {
		return nil, errors.New("DAT literal out of range")
	}
	datVal := binary.LittleEndian.Uint16(buf[datOff:])

	// mov.l @(disp,PC),r2 is 4 instructions later (add/cmp/hi/bt in between) -> byte 30.
	movlOff := fnOff + 30
	ptrOff, err := movlPCRelTarget(buf, movlOff)
	if err != nil {
		return nil, err
	}
	if ptrOff+4 > len(buf) {
		return nil, errors.New("PTR literal out of range")
	}
	ptrVal := binary.LittleEndian.Uint32(buf[ptrOff:])

	datArray := ptrVal - 4

	return &ScreenStateDebuggerAnalysisResult{
		DatVal:   datVal,
		PtrTable: ptrVal,
		DatArray: datArray,
	}, nil
}

func OtherStatesAnalysis(buf []byte) (*OtherStatesAnalysisResult, error) {
	fnOff := findSig(buf, otherStatesSigBytes, otherStatesSigMask)
	if fnOff == -1 {
		return nil, errors.New("signature not found")
	}

	// mov.w @(disp,PC),r2 at +22 -> count literal
	datOff, err := movwPCRelTarget(buf, fnOff+22)
	if err != nil {
		return nil, err
	}
	if datOff < 0 || datOff+2 > len(buf) {
		return nil, errors.New("DAT literal out of range")
	}

	addWord := binary.LittleEndian.Uint16(buf[fnOff+24:])
	if addWord&0xFF00 != 0x7300 {
		return nil, fmt.Errorf("not add #imm,r3 at off %#x (word=%#04x)", fnOff+24, addWord)
	}
	imm := int8(addWord & 0xFF)
	if imm >= 0 {
		return nil, fmt.Errorf("unexpected non-negative index offset %d", imm)
	}
	first := uint32(-imm)

	// mov.l @(disp,PC),r2 at +30 -> pointer literal
	ptrOff, err := movlPCRelTarget(buf, fnOff+30)
	if err != nil {
		return nil, err
	}
	if ptrOff < 0 || ptrOff+4 > len(buf) {
		return nil, errors.New("PTR literal out of range")
	}
	ptrVal := binary.LittleEndian.Uint32(buf[ptrOff:])

	return &OtherStatesAnalysisResult{
		DatVal:     binary.LittleEndian.Uint16(buf[datOff:]),
		PtrTable:   ptrVal,
		DatArray:   ptrVal - first*4,
		FirstIndex: first,
	}, nil
}

func ExtractAllStateTables(binaryData []byte, sections *[]wince.Section) ([]string, []string, error) {
	debugState := os.Getenv("SCREENSTATE_DEBUG") == "true"
	res, err := ScreenStateDebuggerAnalysis(binaryData)
	if err != nil {
		fmt.Println("screen states error:", err)
		return nil, nil, fmt.Errorf("screen states error: %w", err)
	}
	otherRes, err := OtherStatesAnalysis(binaryData)
	if err != nil {
		return nil, nil, fmt.Errorf("other states error: %w", err)
	}

	var textSection *wince.Section = nil
	var dataSection *wince.Section = nil

	for _, section := range *sections {
		if section.Name == ".data" {
			dataSection = &section
		} else if section.Name == ".text" {
			textSection = &section
		}
	}

	if dataSection == nil {
		return nil, nil, errors.New("could not find .data section")
	}

	if textSection == nil {
		return nil, nil, errors.New("could not find .text section")
	}

	// Main states

	var stateTable []string
	var firstItemOffset = int(res.DatArray - dataSection.RealAddr)
	for i := 0; i < int(res.DatVal+2); i++ {
		p := firstItemOffset + i*4
		stringAddr := binary.LittleEndian.Uint32(dataSection.Data[p : p+4])
		if debugState {
			fmt.Println(fmt.Sprintf("ADDR %08x", stringAddr))
		}

		strOff := stringAddr - textSection.RealAddr // uint32 wraps if the address is below the section
		s, ok := cStringAt(textSection.Data, strOff)
		if !ok {
			if debugState {
				fmt.Printf("MAIN  ADDR %08x -> INVALID\n", stringAddr)
			}
			stateTable = append(stateTable, "")
			continue
		}
		stateTable = append(stateTable, s)
		if debugState {
			fmt.Printf("MAIN  ADDR %08x -> %q\n", stringAddr, s)
		}
	}

	// Other states
	var otherStateTable []string
	firstItemOffset = int(otherRes.DatArray - dataSection.RealAddr)

	for i := 0; i < int(otherRes.DatVal+2); i++ {
		p := firstItemOffset + i*4
		stringAddr := binary.LittleEndian.Uint32(dataSection.Data[p : p+4])
		if debugState {
			fmt.Println(fmt.Sprintf("ADDR %08x", stringAddr))
		}

		strOff := stringAddr - textSection.RealAddr // uint32 wraps if the address is below the section
		s, ok := cStringAt(textSection.Data, strOff)
		if !ok {
			if debugState {
				fmt.Printf("OTHER ADDR %08x -> INVALID\n", stringAddr)
			}
			otherStateTable = append(otherStateTable, "")
			continue
		}
		otherStateTable = append(otherStateTable, s)
		if debugState {
			fmt.Printf("OTHER ADDR %08x -> %q\n", stringAddr, s)
		}
	}

	return stateTable, otherStateTable, nil
}

// GetTimer5SecDataAddr Finds address+offset(in section) location of 5000 ms timer duration for identifying it in binary
func GetTimer5SecDataAddr(textSection *wince.Section) (uint32, uint32) {
	pattern := []byte{0x00, 0x35, 0x30, 0x30, 0x30, 0x00, 0x00}
	addr, offset := findInSection(textSection, pattern)
	if addr != 0 {
		return addr + 1, offset + 1
	}
	return 0, 0
}

// GetTimer2SecDataAddr Finds address+offset(in section) location of 2000 ms timer duration for swap
func GetTimer2SecDataAddr(textSection *wince.Section) (uint32, uint32) {
	pattern := []byte{0x00, 0x32, 0x30, 0x30, 0x30, 0x00, 0x00}
	addr, offset := findInSection(textSection, pattern)
	if addr != 0 {
		return addr + 1, offset + 1
	}
	return 0, 0
}

func GetTimerDelayPtrAddress(textSection *wince.Section, initFuncAddr uint32, fiveSecAddr uint32) (uint32, uint32) {
	addrBytes := make([]byte, 4)

	textoffset := initFuncAddr - (*textSection).RealAddr
	binary.LittleEndian.PutUint32(addrBytes, fiveSecAddr)

	maxCap := int(textoffset + 400) // enough slack in case functions differ a bit
	if maxCap > len((*textSection).Data) {
		maxCap = len((*textSection).Data)
	}

	for from := int(textoffset); from < maxCap; {
		i := bytes.Index((*textSection).Data[from:], addrBytes)
		if i < 0 {
			break
		}
		return (*textSection).RealAddr + uint32(from+i), uint32(from + i)
	}
	return 0, 0
}

func GetSCTAgreeClickCodeAddress(textSection *wince.Section, otherStatesTable *[]string, eventHandlerAddress uint32) (uint32, uint32, error) {
	textOffset := eventHandlerAddress - (*textSection).RealAddr

	addrBytes := []byte{0x0b, 0x00, 0xf6, 0x68, 0xff, 0xff} // FFFF replaced with SK_SCT_AGREE_CLICK
	agreeClickCode := slices.Index(*otherStatesTable, "SK_SCT_AGREE_CLICK")
	if agreeClickCode == -1 {
		return 0, 0, errors.New("could not find SK_SCT_AGREE_CLICK")
	}

	binary.LittleEndian.PutUint16(addrBytes[4:], uint16(agreeClickCode))

	maxCap := int(textOffset + 400)
	if maxCap > len((*textSection).Data) {
		maxCap = len((*textSection).Data)
	}

	for from := int(textOffset); from < maxCap; {
		i := bytes.Index((*textSection).Data[from:], addrBytes)
		if i < 0 {
			break
		}
		return ((*textSection).RealAddr + uint32(from+i)) + 4, uint32(from+i) + 4, nil
	}

	return 0, 0, errors.New("could not find at eventHandlerAddress")
}

func FindTransitionActuatorFunctionTransitionIDAddr1(textSection *wince.Section, statesTable *[]string) (uint32, uint32, error) {

	addrBytes := []byte{0x1f, 0xa0, 0x09, 0x00, 0xff, 0xff} // FFFF replaced with TRANSITION_AGREE_TELEMA_STARTING
	agreeClickCode := slices.Index(*statesTable, "TRANSITION_AGREE_TELEMA_STARTING")
	if agreeClickCode == -1 {
		return 0, 0, errors.New("could not find TRANSITION_AGREE_TELEMA_STARTING")
	}

	binary.LittleEndian.PutUint16(addrBytes[4:], uint16(agreeClickCode))

	for from := 0; from < len((*textSection).Data); {
		i := bytes.Index((*textSection).Data[from:], addrBytes)
		if i < 0 {
			break
		}
		return ((*textSection).RealAddr + uint32(from+i)) + 6, uint32(from+i) + 6, nil
	}

	return 0, 0, errors.New("could not find transition actuator function")
}

func FindTransitionActuatorFunctionTransitionIDAddr2(textSection *wince.Section, statesTable *[]string) (uint32, uint32, error) {
	addrBytes := []byte{0x0a, 0xa0, 0x09, 0x00, 0xff, 0xff} // FFFF replaced with SRT_COLD_I_AGREE_TELEMA
	agreeClickCode := slices.Index(*statesTable, "SRT_COLD_I_AGREE_TELEMA")
	if agreeClickCode == -1 {
		return 0, 0, errors.New("could not find SRT_COLD_I_AGREE_TELEMA")
	}

	binary.LittleEndian.PutUint16(addrBytes[4:], uint16(agreeClickCode))

	for from := 0; from < len((*textSection).Data); {
		i := bytes.Index((*textSection).Data[from:], addrBytes)
		if i < 0 {
			break
		}
		return ((*textSection).RealAddr + uint32(from+i)) + 4, uint32(from+i) + 4, nil
	}

	return 0, 0, errors.New("could not find transition actuator function")
}

func RunPatch_AgreeQY7(nbKernel *[]byte) ([]byte, error) {
	var ex *wince.Extractor
	ex, err := wince.NewExtractor(*nbKernel)
	if err != nil {
		return nil, err
	}

	var module *wince.Module = nil

	for _, m := range ex.Modules {
		if m.Name == "ScreenStateCC.dll" {
			module = m
			break
		}
	}

	if module == nil {
		return nil, errors.New("cannot find ScreenStateCC.dll")
	}

	sections, err := module.Sections()
	if err != nil {
		return nil, err
	}

	dllBytes, err := module.Image()
	if err != nil {
		return nil, err
	}

	table, otherTable, err := ExtractAllStateTables(dllBytes, &sections)

	if err != nil {
		return nil, err
	}

	var textSection *wince.Section = nil
	for _, section := range sections {
		if section.Name == ".text" {
			textSection = &section
		}
	}

	if textSection == nil {
		return nil, errors.New("cannot find .text section")
	}

	var textSectionPatched = make([]byte, len((*textSection).Data))
	copy(textSectionPatched, (*textSection).Data)

	inits, err := FindClassInitializers(sections, 0x54, 26)
	if err != nil {
		return nil, err
	}
	var clsSrtColdIAgreeTelemaOkSelected *ClassInitializer = nil
	var clsSrtColdIAgreeTelema *ClassInitializer = nil

	for _, c := range inits {
		if c.ID > 0 {
			if table[c.ID] == "SRT_COLD_I_AGREE_TELEMA" {
				clsSrtColdIAgreeTelema = &c
			} else if table[c.ID] == "SRT_COLD_I_AGREE_TELEMA_OK_SELECTED" {
				clsSrtColdIAgreeTelemaOkSelected = &c
			}
		}
	}

	if clsSrtColdIAgreeTelema == nil {
		return nil, errors.New("cannot find SRT_COLD_I_AGREE_TELEMA")
	}

	if clsSrtColdIAgreeTelemaOkSelected == nil {
		return nil, errors.New("cannot find SRT_COLD_I_AGREE_TELEMA_OK_SELECTED")
	}

	// Patch event handler ID from SRT_COLD_I_AGREE_TELEMA to SRT_COLD_I_AGREE_TELEMA_OK_SELECTED
	coldAgreeTelemaOkSelectedVtableOffset := clsSrtColdIAgreeTelemaOkSelected.VtableVA - textSection.RealAddr

	addrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(addrBytes, clsSrtColdIAgreeTelema.VtableContent[vtEventListenerOffset])

	copy(textSectionPatched[coldAgreeTelemaOkSelectedVtableOffset+(vtEventListenerOffset*4):], addrBytes)

	// Patch event handler ID from SK_SCT_AGREE_CLICK to SS_TMR_AGREE_TELEMA_OK_SELECTED
	agreeClickCode := slices.Index(otherTable, "SS_TMR_AGREE_TELEMA_OK_SELECTED")
	if agreeClickCode == -1 {
		return nil, errors.New("could not find SS_TMR_AGREE_TELEMA_OK_SELECTED")
	}

	_, sctOffset, err := GetSCTAgreeClickCodeAddress(textSection, &otherTable, clsSrtColdIAgreeTelema.VtableContent[vtEventListenerOffset])

	if err != nil {
		return nil, err
	}

	actionIdBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(actionIdBytes, uint16(agreeClickCode))
	copy(textSectionPatched[sctOffset:], actionIdBytes)

	// Patch timer interval for Auto-Agree from 5sec to 2sec

	fiveSecAddr, _ := GetTimer5SecDataAddr(textSection)
	twoSecAddr, _ := GetTimer2SecDataAddr(textSection)

	if fiveSecAddr == 0 {
		return nil, errors.New("fiveSecAddr is 0")
	}

	if twoSecAddr == 0 {
		return nil, errors.New("twoSecAddr is 0")
	}

	_, init1Offset := GetTimerDelayPtrAddress(textSection, clsSrtColdIAgreeTelemaOkSelected.VtableContent[vtInit1Offset], fiveSecAddr)
	_, init2Offset := GetTimerDelayPtrAddress(textSection, clsSrtColdIAgreeTelemaOkSelected.VtableContent[vtInit2Offset], fiveSecAddr)

	if init1Offset == 0 || init2Offset == 0 {
		return nil, errors.New(fmt.Sprintf("init offsets invalid, init1Offset %d, init2Offset %d", init1Offset, init2Offset))
	}

	twoSecondAddrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(twoSecondAddrBytes, twoSecAddr)
	copy(textSectionPatched[init1Offset:], twoSecondAddrBytes)
	copy(textSectionPatched[init2Offset:], twoSecondAddrBytes)

	// Patch startup state machine processor to use SRT_COLD_I_AGREE_TELEMA_OK_SELECTED instead of SRT_COLD_I_AGREE_TELEMA
	agreeTransitionCode := slices.Index(table, "SRT_COLD_I_AGREE_TELEMA_OK_SELECTED")
	if agreeTransitionCode == -1 {
		return nil, errors.New("could not find SRT_COLD_I_AGREE_TELEMA_OK_SELECTED")
	}

	_, transitionOffset1, err := FindTransitionActuatorFunctionTransitionIDAddr1(textSection, &otherTable)
	if err != nil {
		return nil, err
	}
	_, transitionOffset2, err := FindTransitionActuatorFunctionTransitionIDAddr2(textSection, &table)
	if err != nil {
		return nil, err
	}

	transitionIdBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(transitionIdBytes, uint16(agreeTransitionCode))
	copy(textSectionPatched[transitionOffset1:], transitionIdBytes)
	copy(textSectionPatched[transitionOffset2:], transitionIdBytes)

	// Pack .text back to ROM
	err = module.ReplaceSectionByName(".text", textSectionPatched)
	if err != nil {
		return nil, err
	}
	return ex.Bytes(), nil
}
