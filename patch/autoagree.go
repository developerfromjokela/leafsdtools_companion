// Package patch implements navigation firmware patches for Clarion QY8xxx head units (Nissan Leaf).
//
// The auto-agree patch is a Go port of tools/qy8/autoagree.py from albertbm/qemu-clarion
// (branch qy8-gps, commit de1c75cd dated 2026-10-04).
// Upstream source: https://github.com/albertbm/qemu-clarion/blob/qy8-gps/tools/qy8/autoagree.py
// Author: albertbm <https://github.com/albertbm>
package patch

import (
	"LeafSDTools_Companion/patch/c_lz4"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

type PatchMode string

const (
	ModeSkip  PatchMode = "skip"
	ModeTimer PatchMode = "timer"
)

type SkipConfig struct {
	VA         uint32
	Tail       uint32
	PTrue      uint32
	VarSkip    uint32
	VarAgree   uint32
	VarStartup uint32
	Action     uint32
	Ctrl       uint32
	Notify     uint32
	Stock      []uint32
}

type TimerConfig struct {
	VA         uint32
	Tail       uint32
	PTrue      uint32
	PFalse     uint32
	VarStartup uint32
	Event      uint32
	Stock      []uint32
}

type BuildConfig struct {
	Name       string
	ModLen     int64
	Sec0File   uint32
	Sec0VA     uint32
	GetContext uint32
	SetVar     uint32
	CheckVar   uint32
	GetState   uint32
	GetState2  uint32
	EvHandler  uint32
	ExecFn     uint32
	SetTimer   uint32
	Skip       *SkipConfig
	Timer      *TimerConfig
}

var Builds = map[string]*BuildConfig{
	"G218ENNI.120": { // ZE1, 2018+
		Name:       "G218ENNI.120",
		ModLen:     31984640,
		Sec0File:   0xa7c000,
		Sec0VA:     0x413d1000,
		GetContext: 0x41b2f560,
		SetVar:     0x41b2f3d0,
		CheckVar:   0x41b2f3e0,
		GetState:   0x41b2f430,
		GetState2:  0x41b2f3f0,
		EvHandler:  0x41b2f640,
		ExecFn:     0x41b2f5b0,
		SetTimer:   0x41b2f650,
		Skip: &SkipConfig{
			VA:         0x41a0a5c0,
			Tail:       0x41a0a680,
			PTrue:      0x41a0a690,
			VarSkip:    73,
			VarAgree:   257,
			VarStartup: 628,
			Action:     4892,
			Ctrl:       25,
			Notify:     1687,
			Stock: []uint32{
				0xeb0493e6, 0xe58d0134, 0xe59f20bc, 0xe3a01049, 0xe59d0134,
				0xeb04937d, 0xeb0493e0, 0xe58d0138, 0xe59d0138, 0xeb049391,
				0xe58d013c, 0xe301131c, 0xe59d013c, 0xeb049411, 0xe58d0140,
				0xe59d3140, 0xe3530000, 0x1a000007, 0xeb0493d4, 0xe58d0144,
				0xe59d0144, 0xeb049375, 0xe58d0148, 0xe301131c, 0xe59d0148,
				0xeb049405, 0xe3a03001, 0xe58d3000, 0xea000012,
			},
		},
		Timer: &TimerConfig{
			VA:         0x419b8290,
			Tail:       0x419bb13c,
			PTrue:      0x419b91c8,
			PFalse:     0x419b91cc,
			VarStartup: 628,
			Event:      0xc93,
			Stock: []uint32{
				0xeb05dcb2, 0xe58d0004, 0xe59f2f2c, 0xe3a01f9d, 0xe59d0004,
				0xeb05dc4d, 0xe58d0008, 0xe59d3008, 0xe3530000, 0x0a000005,
				0xeb05dca8, 0xe58d000c, 0xe59f2f00, 0xe3a01f9d, 0xe59d000c,
				0xeb05dc3f, 0xe3a03001, 0xe58d3000, 0xea000b97,
			},
		},
	},
	"G214ELNI.062": { // ZE0, 2014-2017
		Name:       "G214ELNI.062",
		ModLen:     30647808,
		Sec0File:   0xa11000,
		Sec0VA:     0x412e1000,
		GetContext: 0x419d376c,
		SetVar:     0x419d35dc,
		CheckVar:   0x419d35ec,
		GetState:   0x419d363c,
		GetState2:  0x419d35fc,
		EvHandler:  0x419d384c,
		ExecFn:     0x419d37bc,
		SetTimer:   0x419d385c,
		Skip: &SkipConfig{
			VA:         0x418b6488,
			Tail:       0x418b6530,
			PTrue:      0x418b6540,
			VarSkip:    47,
			VarAgree:   223,
			VarStartup: 563,
			Action:     4676,
			Ctrl:       25,
			Notify:     1609,
			Stock: []uint32{
				0xeb0474b7, 0xe58d00d4, 0xe59f20a4, 0xe3a0102f, 0xe59d00d4,
				0xeb04744e, 0xeb0474b1, 0xe58d00d8, 0xe59d00d8, 0xeb047462,
				0xe58d00dc, 0xe3011244, 0xe59d00dc, 0xeb0474e2, 0xe58d00e0,
				0xe59d30e0, 0xe3530000, 0x1a000007, 0xeb0474a5, 0xe58d00e4,
				0xe59d00e4, 0xeb047446, 0xe58d00e8, 0xe3011244, 0xe59d00e8,
				0xeb0474d6, 0xe3a03001, 0xe58d3000, 0xea00000c,
			},
		},
	},
}

func ssum(b []byte) uint32 {
	var sum uint32
	n := len(b) / 4
	for i := 0; i < n; i++ {
		sum += binary.LittleEndian.Uint32(b[i*4 : i*4+4])
	}
	return sum
}

func bl(at, to uint32) uint32 {
	return 0xeb000000 | (((to - (at + 8)) >> 2) & 0xffffff)
}

func b_(at, to uint32) uint32 {
	return 0xea000000 | (((to - (at + 8)) >> 2) & 0xffffff)
}

func beq(at, to uint32) uint32 {
	return 0x0a000000 | (((to - (at + 8)) >> 2) & 0xffffff)
}

func bne(at, to uint32) uint32 {
	return 0x1a000000 | (((to - (at + 8)) >> 2) & 0xffffff)
}

func movw(rd, imm uint32) (uint32, error) {
	if imm > 0xffff {
		return 0, fmt.Errorf("immediate out of 16-bit range for movw: %d (max 65535)", imm)
	}
	return 0xe3000000 | ((imm >> 12) << 16) | (rd << 12) | (imm & 0xfff), nil
}

func mov(rd, imm uint32) (uint32, error) {
	for rot := uint32(0); rot < 16; rot++ {
		v := ((imm << (2 * rot)) | (imm >> (32 - 2*rot))) & 0xffffffff
		if v < 0x100 {
			return 0xe3a00000 | (rot << 8) | (rd << 12) | v, nil
		}
	}
	return 0, fmt.Errorf("%d is not an ARM immediate", imm)
}

func movi(rd, imm uint32) (uint32, error) {
	if m, err := mov(rd, imm); err == nil {
		return m, nil
	}
	return movw(rd, imm)
}

func ldrPC(at, rd, to uint32) (uint32, error) {
	if to < at+8 {
		return 0, fmt.Errorf("pc-relative load negative offset: to=%#x, at+8=%#x", to, at+8)
	}
	off := to - (at + 8)
	if off > 0xfff {
		return 0, fmt.Errorf("pc-relative load out of range: %#x", off)
	}
	return 0xe59f0000 | (rd << 12) | off, nil
}

func skipBody(b *BuildConfig, p *SkipConfig) ([]byte, error) {
	a := p.VA
	done := p.VA + 0x68
	ldr0, err := ldrPC(a+0x04, 2, p.PTrue)
	if err != nil {
		return nil, err
	}
	ldr1, err := ldrPC(a+0x14, 2, p.PTrue)
	if err != nil {
		return nil, err
	}
	ldr2, err := ldrPC(a+0x24, 2, p.PTrue)
	if err != nil {
		return nil, err
	}

	mSkip, err := movi(1, p.VarSkip)
	if err != nil {
		return nil, err
	}
	mAgree, err := movi(1, p.VarAgree)
	if err != nil {
		return nil, err
	}
	mStartup, err := movi(1, p.VarStartup)
	if err != nil {
		return nil, err
	}
	mNotify, err := movw(2, p.Notify)
	if err != nil {
		return nil, err
	}
	mCtrl, err := movi(1, p.Ctrl)
	if err != nil {
		return nil, err
	}
	mAction1, err := movw(1, p.Action)
	if err != nil {
		return nil, err
	}
	mAction2, err := movw(1, p.Action)
	if err != nil {
		return nil, err
	}

	w := []uint32{
		bl(a+0x00, b.GetContext),
		ldr0,
		mSkip,
		bl(a+0x0c, b.SetVar), // VAR_CWS_AGREE_SKIP = "true" -> no screen
		bl(a+0x10, b.GetContext),
		ldr1,
		mAgree,
		bl(a+0x1c, b.SetVar), // VAR_I_AGREE_STATUS = "true"
		bl(a+0x20, b.GetContext),
		ldr2,
		mStartup,
		bl(a+0x2c, b.SetVar), // VAR_START_UP_I_AGREE_STATUS = "true"
		bl(a+0x30, b.GetContext),
		mNotify,
		mCtrl,
		bl(a+0x3c, b.ExecFn), // TELEMA_NOTIFY_AGREE
		bl(a+0x40, b.GetContext),
		bl(a+0x44, b.GetState),
		mAction1,
		bl(a+0x4c, b.EvHandler),
		0xe3500000, // cmp r0, #0
		bne(a+0x54, done),
		bl(a+0x58, b.GetContext),
		bl(a+0x5c, b.GetState2),
		mAction2,
		bl(a+0x64, b.EvHandler),
		0xe3a03001, // done: mov r3, #1
		0xe58d3000, // str r3, [sp]
		b_(a+0x70, p.Tail),
	}

	buf := make([]byte, len(w)*4)
	for i, val := range w {
		binary.LittleEndian.PutUint32(buf[i*4:], val)
	}
	return buf, nil
}

func timerBody(b *BuildConfig, p *TimerConfig, delayMs uint32) ([]byte, error) {
	if delayMs == 0 || delayMs > 65535 {
		return nil, fmt.Errorf("timer delay must be between 1 and 65535 ms (got %d)", delayMs)
	}

	a := p.VA
	skip := p.VA + 0x28
	ldr0, err := ldrPC(a+0x04, 2, p.PFalse)
	if err != nil {
		return nil, err
	}
	ldr1, err := ldrPC(a+0x1c, 2, p.PTrue)
	if err != nil {
		return nil, err
	}

	mStartup1, err := movi(1, p.VarStartup)
	if err != nil {
		return nil, err
	}
	mStartup2, err := movi(1, p.VarStartup)
	if err != nil {
		return nil, err
	}
	mEvent, err := movw(1, p.Event)
	if err != nil {
		return nil, err
	}
	mDelay, err := movw(2, delayMs)
	if err != nil {
		return nil, err
	}

	w := []uint32{
		bl(a+0x00, b.GetContext),
		ldr0,
		mStartup1,
		bl(a+0x0c, b.CheckVar), // CheckVariable(628, "false")
		0xe3500000,             // cmp r0, #0
		beq(a+0x14, skip),
		bl(a+0x18, b.GetContext),
		ldr1,
		mStartup2,
		bl(a+0x24, b.SetVar),
		bl(a+0x28, b.GetContext), // skip:
		mEvent,
		mDelay,
		bl(a+0x34, b.SetTimer), // SetEventTimer(SK_SCT_AGREE_CLICK, delayMs)
		0xe3a03001,             // mov r3, #1
		0xe58d3000,             // str r3, [sp]
		b_(a+0x40, p.Tail),
		0xe1a00000, // nop
		0xe1a00000,
	}

	buf := make([]byte, len(w)*4)
	for i, val := range w {
		binary.LittleEndian.PutUint32(buf[i*4:], val)
	}
	return buf, nil
}

func loaderSum(m []byte, segOff int, cnt int) uint32 {
	t := ssum(m[segOff : segOff+0x20+cnt*0x20])
	p := segOff + 512
	for k := 0; k < cnt; k++ {
		cs := int(binary.LittleEndian.Uint32(m[segOff+0x20+k*0x20 : segOff+0x20+k*0x20+4]))
		t += ssum(m[p : p+cs*512])
		p += cs * 512
	}
	return t
}

type ChunkEntry struct {
	Index   int
	Offset  int
	Sectors int
	UncSize int
	CmpSize int
	UncBase int
}

type PatchResult struct {
	BuildName    string
	Mode         PatchMode
	ModOffset    int64
	ModLength    int64
	ChunkIndex   int
	OldChunkSize int
	NewChunkSize int
	SpareBytes   int
	PagesChanged int
	SHA256       string
}

// readSectorAt reads a 512-byte sector at the specified byte offset, with fallback for 4K-native devices.
func readSectorAt(r io.ReaderAt, at int64) ([]byte, error) {
	sec := make([]byte, 512)
	if _, err := r.ReadAt(sec, at); err == nil {
		return sec, nil
	}
	// Fallback for raw character devices requiring 4096-byte alignment
	alignedAt := (at / 4096) * 4096
	buf4k := make([]byte, 4096)
	if _, err := r.ReadAt(buf4k, alignedAt); err == nil {
		diff := int(at - alignedAt)
		if diff+512 <= len(buf4k) {
			copy(sec, buf4k[diff:diff+512])
			return sec, nil
		}
	}
	return nil, fmt.Errorf("failed to read sector at offset %#x", at)
}

// FindMod scans r at 512-byte boundaries for a known navigation .mod header.
// It uses sector-aligned reads to ensure compatibility with raw devices (/dev/rdiskN, O_DIRECT).
func FindMod(r io.ReaderAt, size int64) (int64, *BuildConfig, error) {
	step := int64(1 << 20)
	off := int64(0)
	buf := make([]byte, step+0x200)

	for {
		if size > 0 && off >= size {
			break
		}
		readLen := step + 0x200
		if size > 0 && off+readLen > size {
			readLen = size - off
		}
		// Align readLen to 512 bytes for raw device compatibility
		if readLen%512 != 0 {
			readLen = (readLen / 512) * 512
		}
		if readLen == 0 {
			break
		}

		n, err := r.ReadAt(buf[:readLen], off)
		if n <= 0 {
			break
		}
		chunk := buf[:n]

		for name, b := range Builds {
			needle := []byte(name)
			pos := 0
			for {
				idx := bytes.Index(chunk[pos:], needle)
				if idx < 0 {
					break
				}
				i := pos + idx
				at := off + int64(i) - 0x16
				if at >= 0 && at%512 == 0 {
					// Check header: first see if it's already in chunk memory
					chunkOffset := int(at - off)
					var sec []byte
					if chunkOffset >= 0 && chunkOffset+512 <= len(chunk) {
						sec = chunk[chunkOffset : chunkOffset+512]
					} else {
						// Otherwise perform a sector-aligned read
						var sErr error
						sec, sErr = readSectorAt(r, at)
						if sErr != nil {
							pos = i + 1
							continue
						}
					}

					modLen := int64(binary.LittleEndian.Uint32(sec[:4])) + 0x200
					if modLen == b.ModLen {
						return at, b, nil
					}
				}
				pos = i + 1
			}
		}

		if err != nil {
			break
		}
		off += step
	}

	return 0, nil, errors.New("no nav image known to this patcher was found")
}

// detectAlreadyPatched checks whether the .mod or its target chunk is already patched.
func detectAlreadyPatched(plain []byte, lo int, b *BuildConfig, m []byte, segOff int) (bool, string) {
	// 1. Check if chunk matches skip body
	if b.Skip != nil {
		sb, err := skipBody(b, b.Skip)
		if err == nil && len(plain) >= lo+len(sb) && bytes.Equal(plain[lo:lo+len(sb)], sb) {
			return true, "skip mode"
		}
	}

	// 2. Check if chunk matches timer body (allowing any 16-bit delay in movw at +0x30)
	if b.Timer != nil {
		tbTemplate, err := timerBody(b, b.Timer, 2000)
		tbLen := len(tbTemplate)
		if err == nil && len(plain) >= lo+tbLen {
			curr := plain[lo : lo+tbLen]
			match := true
			for i := 0; i < tbLen; i += 4 {
				if i == 0x30 {
					// Verify instruction at 0x30 is movw r2, #imm (0xe3002000 | ...)
					u := binary.LittleEndian.Uint32(curr[i : i+4])
					if (u & 0xfff0f000) != 0xe3002000 {
						match = false
						break
					}
					continue
				}
				if !bytes.Equal(curr[i:i+4], tbTemplate[i:i+4]) {
					match = false
					break
				}
			}
			if match {
				return true, "timer mode"
			}
		}
	}

	// 3. Check if compensating word at MTCP+0x1c is non-zero
	if segOff+0x20 <= len(m) {
		if binary.LittleEndian.Uint32(m[segOff+0x1c:segOff+0x20]) != 0 {
			return true, "compensating word present at MTCP+0x1c"
		}
	}

	return false, ""
}

// CheckModStatus examines an in-memory .mod image and determines if it is stock, already patched, or corrupt.
func CheckModStatus(m []byte, b *BuildConfig) (isStock bool, patchedMode string, err error) {
	if int64(len(m)) < b.ModLen {
		return false, "", fmt.Errorf("corrupt image: size %d is smaller than expected .mod length %d", len(m), b.ModLen)
	}
	if len(m) < 0x220 {
		return false, "", errors.New("corrupt image: header too small")
	}

	segOff := 0x200
	segSz := int(binary.LittleEndian.Uint32(m[0x98:0x9c]))
	if segSz < 0x20 || segOff+segSz > len(m) {
		return false, "", fmt.Errorf("corrupt image: invalid segment size %d", segSz)
	}

	cnt := int(binary.LittleEndian.Uint32(m[segOff+4 : segOff+8]))
	if cnt <= 0 || cnt > 1024 || segOff+0x20+cnt*0x20 > segOff+segSz {
		return false, "", fmt.Errorf("corrupt image: invalid chunk count %d", cnt)
	}

	// Use skip config as representative for chunk location
	va := b.Skip.VA
	romOff := int(b.Sec0File + (va - b.Sec0VA))

	q := segOff + 512
	uo := 0
	var targetChunk *ChunkEntry

	for k := 0; k < cnt; k++ {
		entryOffset := segOff + 0x20 + k*0x20
		cs := int(binary.LittleEndian.Uint32(m[entryOffset : entryOffset+4]))
		usz := int(binary.LittleEndian.Uint32(m[entryOffset+4 : entryOffset+8]))
		csz := int(binary.LittleEndian.Uint32(m[entryOffset+8 : entryOffset+12]))
		if cs <= 0 || usz <= 0 || csz <= 0 || q+cs*512 > len(m) || q+csz > len(m) {
			return false, "", fmt.Errorf("corrupt image: chunk %d has invalid parameters", k)
		}
		if uo <= romOff && romOff < uo+usz {
			targetChunk = &ChunkEntry{
				Index:   k,
				Offset:  q,
				Sectors: cs,
				UncSize: usz,
				CmpSize: csz,
				UncBase: uo,
			}
		}
		uo += usz
		q += cs * 512
	}

	if targetChunk == nil {
		return false, "", fmt.Errorf("corrupt image: could not find chunk for ROM offset %#x", romOff)
	}

	lo := romOff - targetChunk.UncBase
	plain, err := c_lz4.Decompress(m[targetChunk.Offset:targetChunk.Offset+targetChunk.CmpSize], targetChunk.UncSize)
	if err != nil {
		return false, "", fmt.Errorf("failed to decompress chunk %d: %w", targetChunk.Index, err)
	}

	if patched, mode := detectAlreadyPatched(plain, lo, b, m, segOff); patched {
		return false, mode, nil
	}

	want := make([]byte, len(b.Skip.Stock)*4)
	for i, val := range b.Skip.Stock {
		binary.LittleEndian.PutUint32(want[i*4:], val)
	}
	if lo+len(want) <= len(plain) && bytes.Equal(plain[lo:lo+len(want)], want) {
		return true, "", nil
	}

	return false, "", fmt.Errorf("stock body mismatch: code does not match expected stock instructions")
}

// PatchMod patches the in-memory .mod image.
func PatchMod(m []byte, b *BuildConfig, mode PatchMode, delayMs uint32, log func(string)) (*PatchResult, error) {
	if mode != ModeSkip && mode != ModeTimer {
		return nil, fmt.Errorf("invalid patch mode: %s", mode)
	}
	if mode == ModeTimer && b.Timer == nil {
		return nil, fmt.Errorf("timer mode is not supported for build %s", b.Name)
	}
	if mode == ModeTimer && (delayMs == 0 || delayMs > 65535) {
		return nil, fmt.Errorf("timer delay must be between 1 and 65535 ms (got %d)", delayMs)
	}

	// Boundary and corruption validations
	if int64(len(m)) < b.ModLen {
		return nil, fmt.Errorf("image too small: %d bytes (expected %d)", len(m), b.ModLen)
	}
	if len(m) < 0x220 {
		return nil, errors.New("corrupt image: header too small")
	}

	segOff := 0x200
	segSz := int(binary.LittleEndian.Uint32(m[0x98:0x9c]))
	if segSz < 0x20 || segOff+segSz > len(m) {
		return nil, fmt.Errorf("corrupt image: invalid segment size %d", segSz)
	}

	cnt := int(binary.LittleEndian.Uint32(m[segOff+4 : segOff+8]))
	if cnt <= 0 || cnt > 1024 || segOff+0x20+cnt*0x20 > segOff+segSz {
		return nil, fmt.Errorf("corrupt image: invalid chunk count %d", cnt)
	}

	var stock []uint32
	var patchBytes []byte
	var va uint32
	var err error

	if mode == ModeSkip {
		if b.Skip == nil {
			return nil, fmt.Errorf("skip mode is not supported for build %s", b.Name)
		}
		stock = b.Skip.Stock
		va = b.Skip.VA
		patchBytes, err = skipBody(b, b.Skip)
		if err != nil {
			return nil, fmt.Errorf("failed to generate skip patch body: %w", err)
		}
	} else {
		stock = b.Timer.Stock
		va = b.Timer.VA
		patchBytes, err = timerBody(b, b.Timer, delayMs)
		if err != nil {
			return nil, fmt.Errorf("failed to generate timer patch body: %w", err)
		}
	}

	bodyLen := len(stock) * 4
	if len(patchBytes) != bodyLen {
		return nil, fmt.Errorf("patch body length (%d) != stock body length (%d)", len(patchBytes), bodyLen)
	}

	hdrBefore := make([]byte, 0x200)
	copy(hdrBefore, m[:0x200])

	segBefore := ssum(m[segOff : segOff+segSz])

	q := segOff + 512
	uo := 0
	ents := make([]ChunkEntry, 0, cnt)

	for k := 0; k < cnt; k++ {
		entryOffset := segOff + 0x20 + k*0x20
		cs := int(binary.LittleEndian.Uint32(m[entryOffset : entryOffset+4]))
		usz := int(binary.LittleEndian.Uint32(m[entryOffset+4 : entryOffset+8]))
		csz := int(binary.LittleEndian.Uint32(m[entryOffset+8 : entryOffset+12]))
		if cs <= 0 || usz <= 0 || csz <= 0 || q+cs*512 > len(m) || q+csz > len(m) {
			return nil, fmt.Errorf("corrupt image: chunk %d has invalid parameters", k)
		}
		ents = append(ents, ChunkEntry{
			Index:   k,
			Offset:  q,
			Sectors: cs,
			UncSize: usz,
			CmpSize: csz,
			UncBase: uo,
		})
		uo += usz
		q += cs * 512
	}

	romOff := int(b.Sec0File + (va - b.Sec0VA))
	var targetChunk *ChunkEntry
	for i := range ents {
		e := &ents[i]
		if e.UncBase <= romOff && romOff < e.UncBase+e.UncSize {
			targetChunk = e
			break
		}
	}
	if targetChunk == nil {
		return nil, fmt.Errorf("could not find chunk containing ROM offset %#x", romOff)
	}

	lo := romOff - targetChunk.UncBase
	if log != nil {
		log(fmt.Sprintf("%s patch at %#x -> ROM %#x -> chunk %d +%#x", mode, va, romOff, targetChunk.Index, lo))
	}

	plain, err := c_lz4.Decompress(m[targetChunk.Offset:targetChunk.Offset+targetChunk.CmpSize], targetChunk.UncSize)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress chunk %d: %w", targetChunk.Index, err)
	}

	if lo < 0 || lo+bodyLen > len(plain) {
		return nil, fmt.Errorf("corrupt image: patch location %#x exceeds chunk size %d", lo, len(plain))
	}

	// Check if already patched
	if patched, detected := detectAlreadyPatched(plain, lo, b, m, segOff); patched {
		return nil, fmt.Errorf("navigation image is already patched (%s detected)", detected)
	}

	want := make([]byte, bodyLen)
	for i, val := range stock {
		binary.LittleEndian.PutUint32(want[i*4:], val)
	}

	currentBody := plain[lo : lo+bodyLen]
	if !bytes.Equal(currentBody, want) {
		return nil, fmt.Errorf("stock body mismatch: got %s, want %s", hex.EncodeToString(currentBody), hex.EncodeToString(want))
	}

	newPlain := make([]byte, len(plain))
	copy(newPlain, plain)
	copy(newPlain[lo:lo+bodyLen], patchBytes)

	nsrc, err := c_lz4.CompressHC(newPlain, 12)
	if err != nil {
		return nil, fmt.Errorf("failed to recompress chunk %d: %w", targetChunk.Index, err)
	}

	// Verify round-trip decompression
	roundTrip, err := c_lz4.Decompress(nsrc, targetChunk.UncSize)
	if err != nil || !bytes.Equal(roundTrip, newPlain) {
		return nil, fmt.Errorf("recompressed chunk %d failed round-trip verification", targetChunk.Index)
	}

	sectorCap := targetChunk.Sectors * 512
	spare := sectorCap - len(nsrc)
	if log != nil {
		log(fmt.Sprintf("chunk %d: %d -> %d B (sectors hold %d, %d spare)",
			targetChunk.Index, targetChunk.CmpSize, len(nsrc), sectorCap, spare))
	}
	if len(nsrc) > sectorCap {
		return nil, fmt.Errorf("patched chunk (%d B) exceeds allocated sectors (%d B)", len(nsrc), sectorCap)
	}

	// Write recompressed chunk payload padded with zeros
	chunkSlot := m[targetChunk.Offset : targetChunk.Offset+sectorCap]
	copy(chunkSlot, nsrc)
	for i := len(nsrc); i < sectorCap; i++ {
		chunkSlot[i] = 0
	}

	// Update chunk descriptor
	descOffset := segOff + 0x20 + targetChunk.Index*0x20
	binary.LittleEndian.PutUint32(m[descOffset+8:descOffset+12], uint32(len(nsrc)))
	binary.LittleEndian.PutUint32(m[descOffset+12:descOffset+16], ssum(chunkSlot))

	// Compensating word in reserved field MTCP+0x1c
	pad := segOff + 0x1c
	if binary.LittleEndian.Uint32(m[pad:pad+4]) != 0 {
		return nil, errors.New("navigation image is already patched (MTCP+0x1c compensating word already present)")
	}
	drift := segBefore - ssum(m[segOff:segOff+segSz])
	binary.LittleEndian.PutUint32(m[pad:pad+4], drift)

	// Validate checksums
	if ssum(m[segOff:segOff+segSz]) != segBefore {
		return nil, errors.New("segment sum drifted")
	}
	if loaderSum(m, segOff, cnt) != segBefore {
		return nil, errors.New("loader sum drifted")
	}
	expectedSum4 := binary.LittleEndian.Uint32(m[0x34:0x38])
	if ssum(m[0x200:]) != expectedSum4 {
		return nil, errors.New("SUM4 header mismatch")
	}
	if !bytes.Equal(m[:0x200], hdrBefore) {
		return nil, errors.New("512-byte header changed unexpectedly")
	}

	hash := sha256.Sum256(m)
	return &PatchResult{
		BuildName:    b.Name,
		Mode:         mode,
		ChunkIndex:   targetChunk.Index,
		OldChunkSize: targetChunk.CmpSize,
		NewChunkSize: len(nsrc),
		SpareBytes:   spare,
		SHA256:       hex.EncodeToString(hash[:]),
	}, nil
}

type ReadWriterAt interface {
	io.ReaderAt
	io.WriterAt
}

// ApplyAutoAgreePatch searches rwa for a nav .mod image, patches it, writes it back,
// and verifies the written media content.
func ApplyAutoAgreePatch(rwa ReadWriterAt, size int64, mode PatchMode, delayMs uint32, log func(string)) (*PatchResult, error) {
	if log == nil {
		log = func(string) {}
	}
	log("Searching for Clarion nav .mod image...")
	at, b, err := FindMod(rwa, size)
	if err != nil {
		return nil, err
	}
	log(fmt.Sprintf("Found %s at offset %#x (%d bytes)", b.Name, at, b.ModLen))

	m := make([]byte, b.ModLen)
	if _, err := rwa.ReadAt(m, at); err != nil {
		return nil, fmt.Errorf("failed to read .mod: %w", err)
	}

	before := make([]byte, len(m))
	copy(before, m)

	res, err := PatchMod(m, b, mode, delayMs, log)
	if err != nil {
		return nil, err
	}
	res.ModOffset = at
	res.ModLength = b.ModLen

	// Count modified 4KiB pages
	pageSet := make(map[int64]bool)
	for i := range m {
		if m[i] != before[i] {
			pageSet[(at+int64(i))/4096] = true
		}
	}
	res.PagesChanged = len(pageSet)

	log(fmt.Sprintf("Writing patched .mod back (%d 4KiB pages modified)...", res.PagesChanged))
	if _, err := rwa.WriteAt(m, at); err != nil {
		return nil, fmt.Errorf("failed to write patched .mod: %w", err)
	}

	// Flush to storage if underlying handle supports Sync
	if syncer, ok := rwa.(interface{ Sync() error }); ok {
		if err := syncer.Sync(); err != nil {
			log(fmt.Sprintf("Notice: sync returned %v", err))
		}
	}

	// Verification: Re-read the modified data and verify byte-for-byte against patched memory
	log("Verifying written data on media...")
	verifyBuf := make([]byte, b.ModLen)
	if _, err := rwa.ReadAt(verifyBuf, at); err != nil {
		return nil, fmt.Errorf("verification read failed: %w", err)
	}
	if !bytes.Equal(verifyBuf, m) {
		return nil, errors.New("verification failed: media content does not match patched data")
	}
	log("Verification passed: media content matches patched data.")

	log(fmt.Sprintf("Patch applied successfully. SHA256 of .mod: %s", res.SHA256))
	return res, nil
}
