package wince

import "encoding/binary"

var le = binary.LittleEndian

// On-disk sizes of the ROM structures. The Python original used ctypes with
// native alignment; these are the resulting sizes (32-bit pointers).
const (
	romHdrSize    = 84
	tocEntrySize  = 32
	fileEntrySize = 28
	e32RomSize    = 108
	o32RomSize    = 24
)

const (
	romExtra = 9  // number of data directory entries stored in an e32_rom
	stdExtra = 16 // number of data directory entries in a PE header
)

// Indices into the data directory ("unit") arrays.
const (
	unitEXP = 0
	unitIMP = 1
	unitRES = 2
	unitEXC = 3
	unitSEC = 4
	unitFIX = 5
	unitDEB = 6
	unitIMD = 7
	unitMSP = 8
	unitTLS = 9
	unitCBK = 10
	unitRS1 = 11
	unitRS2 = 12
	unitRS3 = 13
	unitRS4 = 14
	unitRS5 = 15
)

// FileTime is a Windows FILETIME (100ns ticks since 1601-01-01 UTC).
type FileTime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

func (ft FileTime) Unix() int64 {
	t := uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
	return int64(t/10000000) - 11644473600
}

type Info struct {
	RVA  uint32
	Size uint32
}

type E32Rom struct {
	ObjCnt      uint16
	ImageFlags  uint16
	EntryRVA    uint32
	VBase       uint32
	SubsysMajor uint16
	SubsysMinor uint16
	StackMax    uint32
	VSize       uint32
	Sect14RVA   uint32
	Sect14Size  uint32
	Unit        [romExtra]Info
	Subsys      uint16
}

type O32Rom struct {
	VSize    uint32
	RVA      uint32
	PSize    uint32
	DataPtr  uint32
	RealAddr uint32
	Flags    uint32
}

type RomHdr struct {
	DllFirst      uint32
	DllLast       uint32
	PhysFirst     uint32
	PhysLast      uint32
	NumMods       uint32
	RAMStart      uint32
	RAMFree       uint32
	RAMEnd        uint32
	CopyEntries   uint32
	CopyOffset    uint32
	ProfileLen    uint32
	ProfileOffset uint32
	NumFiles      uint32
	KernelFlags   uint32
	FSRamPercent  uint32
	DrivGlobStart uint32
	DrivGlobLen   uint32
	CPUType       uint16
	MiscFlags     uint16
	Extensions    uint32
	TrackingStart uint32
	TrackingLen   uint32
}

// TocEntry is a module entry in the ROM table of contents.
type TocEntry struct {
	FileAttributes uint32
	FileTime       FileTime
	FileSize       uint32
	FileNamePtr    uint32
	E32Offset      uint32
	O32Offset      uint32
	LoadOffset     uint32
}

type FileEntry struct {
	FileAttributes uint32
	FileTime       FileTime
	RealFileSize   uint32
	CompFileSize   uint32
	FileNamePtr    uint32
	LoadOffset     uint32
}

type Section struct {
	Index int
	Name  string
	O32Rom
	Compressed  bool
	ImageOffset int64
	Data        []byte
}

// The parse* functions require len(b) >= the respective structure size; the
// caller guarantees that via Extractor.slice.

func parseRomHdr(b []byte) RomHdr {
	u := func(i int) uint32 { return le.Uint32(b[i*4:]) }
	return RomHdr{
		DllFirst: u(0), DllLast: u(1), PhysFirst: u(2), PhysLast: u(3),
		NumMods: u(4), RAMStart: u(5), RAMFree: u(6), RAMEnd: u(7),
		CopyEntries: u(8), CopyOffset: u(9), ProfileLen: u(10), ProfileOffset: u(11),
		NumFiles: u(12), KernelFlags: u(13), FSRamPercent: u(14),
		DrivGlobStart: u(15), DrivGlobLen: u(16),
		CPUType:       le.Uint16(b[68:]),
		MiscFlags:     le.Uint16(b[70:]),
		Extensions:    le.Uint32(b[72:]),
		TrackingStart: le.Uint32(b[76:]),
		TrackingLen:   le.Uint32(b[80:]),
	}
}

func parseTocEntry(b []byte) TocEntry {
	return TocEntry{
		FileAttributes: le.Uint32(b[0:]),
		FileTime:       FileTime{LowDateTime: le.Uint32(b[4:]), HighDateTime: le.Uint32(b[8:])},
		FileSize:       le.Uint32(b[12:]),
		FileNamePtr:    le.Uint32(b[16:]),
		E32Offset:      le.Uint32(b[20:]),
		O32Offset:      le.Uint32(b[24:]),
		LoadOffset:     le.Uint32(b[28:]),
	}
}

func parseFileEntry(b []byte) FileEntry {
	return FileEntry{
		FileAttributes: le.Uint32(b[0:]),
		FileTime:       FileTime{LowDateTime: le.Uint32(b[4:]), HighDateTime: le.Uint32(b[8:])},
		RealFileSize:   le.Uint32(b[12:]),
		CompFileSize:   le.Uint32(b[16:]),
		FileNamePtr:    le.Uint32(b[20:]),
		LoadOffset:     le.Uint32(b[24:]),
	}
}

func parseE32Rom(b []byte) E32Rom {
	e := E32Rom{
		ObjCnt:      le.Uint16(b[0:]),
		ImageFlags:  le.Uint16(b[2:]),
		EntryRVA:    le.Uint32(b[4:]),
		VBase:       le.Uint32(b[8:]),
		SubsysMajor: le.Uint16(b[12:]),
		SubsysMinor: le.Uint16(b[14:]),
		StackMax:    le.Uint32(b[16:]),
		VSize:       le.Uint32(b[20:]),
		Sect14RVA:   le.Uint32(b[24:]),
		Sect14Size:  le.Uint32(b[28:]),
		Subsys:      le.Uint16(b[104:]),
	}
	for i := range e.Unit {
		e.Unit[i] = Info{RVA: le.Uint32(b[32+8*i:]), Size: le.Uint32(b[36+8*i:])}
	}
	return e
}

func parseO32Rom(b []byte) O32Rom {
	return O32Rom{
		VSize:    le.Uint32(b[0:]),
		RVA:      le.Uint32(b[4:]),
		PSize:    le.Uint32(b[8:]),
		DataPtr:  le.Uint32(b[12:]),
		RealAddr: le.Uint32(b[16:]),
		Flags:    le.Uint32(b[20:]),
	}
}
