package wince

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

var (
	ErrExists         = errors.New("wince: file already exists in ROM")
	ErrNoSpace        = errors.New("wince: no free space in ROM image")
	ErrCompressVerify = errors.New("wince: compressed data failed round-trip verification")
)

const (
	numFilesFieldOffset = 48 // NumFiles within RomHdr (u32 index 12)
	attrStored          = 0x007
	attrCompressedFlag  = 0x800
	copyEntrySize       = 16
	allocAlign          = 16
)

// AddFile adds a plain file to the ROM, with optional compression
func (e *Extractor) AddFile(name string, data []byte, compress bool) (*File, error) {
	if err := validEntryName(name); err != nil {
		return nil, err
	}
	for _, f := range e.Files {
		if strings.EqualFold(f.Name, name) {
			return nil, fmt.Errorf("%s: %w", name, ErrExists)
		}
	}
	if int64(len(data)) > MaxUncompressedSize {
		return nil, ErrTooLarge
	}

	payload := data
	attrs := uint32(attrStored)
	if compress && len(data) > 0 {
		comp, err := CECompress(data, 4096)
		if err != nil {
			return nil, err
		}
		if len(comp) < len(data) {
			if err := verifyCompressed(comp, data); err != nil {
				return nil, err
			}
			payload = comp
			attrs |= attrCompressedFlag
		} else {
			fmt.Println("Warning: compressed data is larger than uncompressed, not using compression!")
		}
	}

	// File table slot must be the zeroed area right after the last entry.
	fileBase := e.romHdrOffset + romHdrSize + int64(e.RomHdr.NumMods)*tocEntrySize
	slotOff := fileBase + int64(e.RomHdr.NumFiles)*fileEntrySize
	slot, err := e.slice(slotOff, fileEntrySize)
	if err != nil {
		return nil, fmt.Errorf("file table slot: %w", err)
	}
	if !allZero(slot) {
		return nil, fmt.Errorf("file table slot: %w", ErrNoSpace)
	}

	used := e.usedSpans()
	dataOff, err := e.allocate(int64(max(len(payload), 1)), &used)
	if err != nil {
		return nil, fmt.Errorf("data: %w", err)
	}
	nameOff, err := e.allocate(int64(len(name))+1, &used)
	if err != nil {
		return nil, fmt.Errorf("name: %w", err)
	}

	dataAddr, err := e.addrOf(dataOff)
	if err != nil {
		return nil, err
	}
	nameAddr, err := e.addrOf(nameOff)
	if err != nil {
		return nil, err
	}

	ticks := uint64(time.Now().Unix()+11644473600) * 10000000
	entry := FileEntry{
		FileAttributes: attrs,
		FileTime:       FileTime{LowDateTime: uint32(ticks), HighDateTime: uint32(ticks >> 32)},
		RealFileSize:   uint32(len(data)),
		CompFileSize:   uint32(len(payload)),
		FileNamePtr:    nameAddr,
		LoadOffset:     dataAddr,
	}

	copy(e.data[dataOff:], payload)
	copy(e.data[nameOff:], name)
	putFileEntry(slot, entry)
	e.RomHdr.NumFiles++
	le.PutUint32(e.data[e.romHdrOffset+numFilesFieldOffset:], e.RomHdr.NumFiles)

	f := &File{Name: name, Entry: entry, ext: e}
	e.Files = append(e.Files, f)
	return f, nil
}

func putFileEntry(b []byte, f FileEntry) {
	le.PutUint32(b[0:], f.FileAttributes)
	le.PutUint32(b[4:], f.FileTime.LowDateTime)
	le.PutUint32(b[8:], f.FileTime.HighDateTime)
	le.PutUint32(b[12:], f.RealFileSize)
	le.PutUint32(b[16:], f.CompFileSize)
	le.PutUint32(b[20:], f.FileNamePtr)
	le.PutUint32(b[24:], f.LoadOffset)
}

func verifyCompressed(comp, orig []byte) error {
	dec := make([]byte, len(orig)+4096)
	n := ceDecompressROM(comp, len(comp), dec, len(orig), 0, 1, 4096)
	if n != len(orig) || !bytes.Equal(dec[:n], orig) {
		return ErrCompressVerify
	}
	return nil
}

func validEntryName(name string) error {
	if name == "" {
		return ErrBadName
	}
	for i := 0; i < len(name); i++ {
		if name[i] == 0 || name[i] >= 0x80 {
			return ErrBadName
		}
	}
	return nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func (e *Extractor) addrOf(off int64) (uint32, error) {
	a := off + e.LoadOffset
	if a < 0 || a > math.MaxUint32 {
		return 0, ErrOutOfRange
	}
	return uint32(a), nil
}

// usedSpans lists the byte ranges (offsets into e.data) occupied by known ROM structures, so new data is never placed over them
func (e *Extractor) usedSpans() []span {
	var s []span
	add := func(lo, n int64) {
		if n > 0 {
			s = append(s, span{lo, lo + n})
		}
	}
	h := e.RomHdr
	tocBase := e.romHdrOffset + romHdrSize
	fileBase := tocBase + int64(h.NumMods)*tocEntrySize

	add(0, romSignatureOffset+12)                                                  // boot area, signature, pointers
	add(e.romHdrOffset, fileBase+int64(h.NumFiles+1)*fileEntrySize-e.romHdrOffset) // header, TOC, file table + new slot

	for _, m := range e.Modules {
		add(e.minusLoadOffset(m.Toc.FileNamePtr), int64(len(m.Name))+1)
		add(e.minusLoadOffset(m.Toc.E32Offset), e32RomSize)
		add(e.minusLoadOffset(m.Toc.O32Offset), int64(len(m.O32s))*o32RomSize)
		for _, o := range m.O32s {
			add(e.minusLoadOffset(o.DataPtr), int64(min(o.VSize, o.PSize)))
		}
	}
	for _, f := range e.Files {
		add(e.minusLoadOffset(f.Entry.FileNamePtr), int64(len(f.Name))+1)
		add(e.minusLoadOffset(f.Entry.LoadOffset), int64(f.Entry.CompFileSize))
	}
	add(e.minusLoadOffset(h.CopyOffset), int64(h.CopyEntries)*copyEntrySize)
	if h.ProfileLen != 0 {
		add(e.minusLoadOffset(h.ProfileOffset), int64(h.ProfileLen))
	}
	return s
}

// allocate finds n zero bytes, 16-byte aligned, that do not overlap any used span
func (e *Extractor) allocate(n int64, used *[]span) (int64, error) {
	lo, hi := int64(0), int64(len(e.data))
	if e.RomHdr.PhysLast > e.RomHdr.PhysFirst {
		lo = max(lo, e.minusLoadOffset(e.RomHdr.PhysFirst))
		hi = min(hi, e.minusLoadOffset(e.RomHdr.PhysLast))
	}

	sp := append([]span(nil), (*used)...)
	sort.Slice(sp, func(i, j int) bool { return sp[i].lo < sp[j].lo })

	find := func(gapLo, gapHi int64) (int64, bool) {
		for p := gapLo; p < gapHi; {
			if e.data[p] != 0 {
				p++
				continue
			}
			q := p
			for q < gapHi && e.data[q] == 0 {
				q++
			}
			start := (p + allocAlign - 1) &^ (allocAlign - 1)
			if start+n <= q {
				return start, true
			}
			p = q
		}
		return 0, false
	}

	cursor := lo
	for _, s := range sp {
		if s.lo > cursor {
			if off, ok := find(cursor, min(s.lo, hi)); ok {
				*used = append(*used, span{off, off + n})
				return off, nil
			}
		}
		cursor = max(cursor, s.hi)
	}
	if cursor < hi {
		if off, ok := find(cursor, hi); ok {
			*used = append(*used, span{off, off + n})
			return off, nil
		}
	}
	return 0, ErrNoSpace
}
