package wince

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	imageDOSSignature            = 0x5A4D
	imageFileRelocsStripped      = 0x0001
	imageScnCntCode              = 0x00000020
	imageScnCntInitializedData   = 0x00000040
	imageScnCntUninitializedData = 0x00000080
	imageScnCompressed           = 0x00002000

	romSignatureOffset = 64
	romSignature       = 0x43454345

	e32ObjNameBytes = 8
)

// Segment kinds used to name the rebuilt PE sections.
const (
	segText = iota
	segData
	segPData
	segRsrc
	segOther
)

var segmentNames = [...]string{".text", ".data", ".pdata", ".rsrc", ".other"}

// Limits applied to sizes that come from the (untrusted) ROM image so a
// crafted image cannot make the library allocate unbounded memory. They may be
// raised before calling into the package if you really need larger files.
var (
	// MaxUncompressedSize is the largest decompressed size accepted for a
	// single file or module section.
	MaxUncompressedSize int64 = 1 << 30
	// MaxImageSize is the largest rebuilt module (PE image) that will be built.
	MaxImageSize int64 = 1 << 30
)

var (
	ErrNoROMSignature      = errors.New("wince: ROM signature not found")
	ErrOutOfRange          = errors.New("wince: offset or size outside of ROM image")
	ErrDecompressionFailed = errors.New("wince: decompression failed")
	ErrTooLarge            = errors.New("wince: size exceeds configured limit")
	ErrBadName             = errors.New("wince: invalid entry name")
	ErrNotFound            = errors.New("wince: not found")
	ErrSizeMismatch        = errors.New("wince: replacement size differs from stored section size")
	ErrCompressedSection   = errors.New("wince: section is compressed; in-place replacement not supported")
)

// Extractor extracts information and files from a Windows CE ROM image.
// All data is read from the in-memory image; slices returned by Data are views
// into it and must not be modified.
type Extractor struct {
	data         []byte
	romHdrOffset int64
	// LoadOffset converts a load address (as stored in a TOC/E32/O32 entry)
	// into a byte offset within data: fileOffset = addr - LoadOffset.
	LoadOffset int64

	// RomHdr is the parsed ROM header.
	RomHdr RomHdr
	// Modules are the executables/DLLs found in the ROM.
	Modules []*Module
	// Files are the plain files found in the ROM.
	Files []*File
	// Start is the offset of the ROM image within the buffer that was passed
	// to NewExtractor/NewExtractorAt. Offsets returned by Offset are relative
	// to Start.
	Start int
	image []byte
}

// NewExtractor scans image for the Windows CE ROM signature and analyzes the
// ROM that starts there.
func NewExtractor(image []byte) (*Extractor, error) {
	start, err := findImageStart(image)
	if err != nil {
		return nil, err
	}
	e, err := analyze(image[start:])
	if err != nil {
		return nil, err
	}
	e.Start = start
	e.image = image
	return e, nil
}

// NewExtractorAt analyzes the ROM that starts at the given offset of image,
// without scanning for the signature.
func NewExtractorAt(image []byte, offset int) (*Extractor, error) {
	if offset < 0 || offset > len(image) {
		return nil, ErrOutOfRange
	}
	e, err := analyze(image[offset:])
	if err != nil {
		return nil, err
	}
	e.Start = offset
	return e, nil
}

// Offset converts a virtual address stored in the ROM (e.g. a module's
// DataPtr or Toc.E32Offset) into an offset relative to Start. The result is
// not range-checked; add Start to index the original buffer and check bounds
// before use.
func (e *Extractor) Offset(va uint32) int64 {
	return e.minusLoadOffset(va)
}

// findImageStart returns the offset of the start of the ROM image: the
// signature sits romSignatureOffset bytes into the image.
func findImageStart(image []byte) (int, error) {
	var sig [4]byte
	le.PutUint32(sig[:], romSignature)

	from := 0
	for from <= len(image)-4 {
		idx := bytes.Index(image[from:], sig[:])
		if idx < 0 {
			break
		}
		pos := from + idx
		if start := pos - romSignatureOffset; start >= 0 {
			return start, nil
		}
		from = pos + 1 // signature too close to the start to be real; keep looking
	}
	return 0, ErrNoROMSignature
}

func analyze(data []byte) (*Extractor, error) {
	e := &Extractor{data: data}

	romHdrOff, err := e.u32(romSignatureOffset + 8)
	if err != nil {
		return nil, err
	}
	loadBase, err := e.u32(romSignatureOffset + 4)
	if err != nil {
		return nil, err
	}
	e.romHdrOffset = int64(romHdrOff)
	e.LoadOffset = int64(loadBase) - e.romHdrOffset

	b, err := e.slice(e.romHdrOffset, romHdrSize)
	if err != nil {
		return nil, err
	}
	e.RomHdr = parseRomHdr(b)

	// Validate the table sizes up front so nothing is allocated for entries
	// that cannot exist.
	tocBase := e.romHdrOffset + romHdrSize
	if _, err := e.slice(tocBase, int64(e.RomHdr.NumMods)*tocEntrySize); err != nil {
		return nil, fmt.Errorf("module table: %w", err)
	}
	fileBase := tocBase + int64(e.RomHdr.NumMods)*tocEntrySize
	if _, err := e.slice(fileBase, int64(e.RomHdr.NumFiles)*fileEntrySize); err != nil {
		return nil, fmt.Errorf("file table: %w", err)
	}

	e.Modules = make([]*Module, 0, e.RomHdr.NumMods)
	for i := int64(0); i < int64(e.RomHdr.NumMods); i++ {
		b, err := e.slice(tocBase+i*tocEntrySize, tocEntrySize)
		if err != nil {
			return nil, err
		}
		m, err := newModule(e, parseTocEntry(b))
		if err != nil {
			return nil, fmt.Errorf("module %d: %w", i, err)
		}
		e.Modules = append(e.Modules, m)
	}

	e.Files = make([]*File, 0, e.RomHdr.NumFiles)
	for i := int64(0); i < int64(e.RomHdr.NumFiles); i++ {
		b, err := e.slice(fileBase+i*fileEntrySize, fileEntrySize)
		if err != nil {
			return nil, err
		}
		f, err := newFile(e, parseFileEntry(b))
		if err != nil {
			return nil, fmt.Errorf("file %d: %w", i, err)
		}
		e.Files = append(e.Files, f)
	}
	return e, nil
}

func (e *Extractor) slice(off, n int64) ([]byte, error) {
	if off < 0 || n < 0 || off > int64(len(e.data))-n {
		return nil, ErrOutOfRange
	}
	return e.data[off : off+n], nil
}

func (e *Extractor) u32(off int64) (uint32, error) {
	b, err := e.slice(off, 4)
	if err != nil {
		return 0, err
	}
	return le.Uint32(b), nil
}

// minusLoadOffset converts an address stored in the ROM to an image offset.
func (e *Extractor) minusLoadOffset(addr uint32) int64 {
	return int64(addr) - e.LoadOffset
}

// cString reads a NUL-terminated ASCII string at off.
func (e *Extractor) cString(off int64) (string, error) {
	if off < 0 || off >= int64(len(e.data)) {
		return "", ErrOutOfRange
	}
	rest := e.data[off:]
	n := bytes.IndexByte(rest, 0)
	if n < 0 {
		return "", ErrBadName
	}
	for _, c := range rest[:n] {
		if c >= 0x80 {
			return "", ErrBadName
		}
	}
	return string(rest[:n]), nil
}

func (e *Extractor) extractData(offset, datasize int64, isCompressed bool, maxUncompressed int64) ([]byte, error) {
	buf, err := e.slice(offset, datasize)
	if err != nil {
		return nil, err
	}
	if datasize == maxUncompressed || !isCompressed {
		return buf, nil
	}
	if maxUncompressed < 0 || maxUncompressed > MaxUncompressedSize {
		return nil, ErrTooLarge
	}

	dec := make([]byte, maxUncompressed+4096)
	n := ceDecompressROM(buf, int(datasize), dec, int(maxUncompressed), 0, 1, 4096)
	if n < 0 || n > len(dec) {
		return nil, ErrDecompressionFailed
	}
	return dec[:n], nil
}

// File is a plain file stored in the ROM.
type File struct {
	Name  string
	Entry FileEntry
	ext   *Extractor
}

func newFile(e *Extractor, entry FileEntry) (*File, error) {
	name, err := e.cString(e.minusLoadOffset(entry.FileNamePtr))
	if err != nil {
		return nil, fmt.Errorf("file name: %w", err)
	}
	return &File{Name: name, Entry: entry, ext: e}, nil
}

// Data returns the file contents, decompressing them if necessary. The slice
// may alias the ROM image and must not be modified.
func (f *File) Data() ([]byte, error) {
	return f.ext.extractData(
		f.ext.minusLoadOffset(f.Entry.LoadOffset),
		int64(f.Entry.CompFileSize),
		f.Entry.CompFileSize != f.Entry.RealFileSize,
		int64(f.Entry.RealFileSize),
	)
}

// WriteTo writes the file contents to w (implements io.WriterTo).
func (f *File) WriteTo(w io.Writer) (int64, error) {
	data, err := f.Data()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(data)
	return int64(n), err
}

// ---------------------------------------------------------------------------
// Modules
// ---------------------------------------------------------------------------

// Module is an executable or DLL stored in the ROM in split (e32/o32) form.
type Module struct {
	Name string
	Toc  TocEntry
	E32  E32Rom
	O32s []O32Rom

	rom RomHdr
	ext *Extractor
}

func newModule(e *Extractor, toc TocEntry) (*Module, error) {
	name, err := e.cString(e.minusLoadOffset(toc.FileNamePtr))
	if err != nil {
		return nil, fmt.Errorf("module name: %w", err)
	}
	m := &Module{Name: name, Toc: toc, rom: e.RomHdr, ext: e}

	b, err := e.slice(e.minusLoadOffset(toc.E32Offset), e32RomSize)
	if err != nil {
		return nil, fmt.Errorf("%s: e32: %w", name, err)
	}
	m.E32 = parseE32Rom(b)

	o32Offset := e.minusLoadOffset(toc.O32Offset)
	m.O32s = make([]O32Rom, 0, m.E32.ObjCnt)
	for i := int64(0); i < int64(m.E32.ObjCnt); i++ {
		b, err := e.slice(o32Offset+i*o32RomSize, o32RomSize)
		if err != nil {
			return nil, fmt.Errorf("%s: o32 %d: %w", name, i, err)
		}
		m.O32s = append(m.O32s, parseO32Rom(b))
	}
	return m, nil
}

// WriteTo rebuilds the module as a PE file and writes it to w.
func (m *Module) WriteTo(w io.Writer) (int64, error) {
	img, err := m.Image()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(img)
	return int64(n), err
}

// Image rebuilds the module as a PE file image.
func (m *Module) Image() ([]byte, error) {
	w := &imageWriter{}
	w.writeDummyMZHeader()

	e32Ofs := w.len()
	w.write(m.buildE32Header())

	o32Ofs := make([]int, len(m.O32s))
	dataOfs := make([]int, len(m.O32s))
	dataLen := make([]int, len(m.O32s))
	var usage [len(segmentNames)]int

	for i, o := range m.O32s {
		o32Ofs[i] = w.len()
		w.write(m.buildO32Header(o, &usage))
	}

	w.align(0x200)
	headerSize := w.len()

	for i, o := range m.O32s {
		dataOfs[i] = w.len()

		data, err := m.ext.extractData(
			m.ext.minusLoadOffset(o.DataPtr),
			int64(min(o.VSize, o.PSize)),
			o.Flags&imageScnCompressed != 0,
			int64(o.VSize),
		)
		if err != nil {
			return nil, fmt.Errorf("%s: section %d: %w", m.Name, i, err)
		}
		if int64(w.len())+int64(len(data)) > MaxImageSize {
			return nil, fmt.Errorf("%s: %w", m.Name, ErrTooLarge)
		}
		w.write(data)
		dataLen[i] = len(data)
		w.align(0x200)
	}

	// Patch the section headers (psize, dataptr) and the PE header size.
	for i := range m.O32s {
		w.putU32(o32Ofs[i]+16, uint32(dataLen[i]))
		w.putU32(o32Ofs[i]+20, uint32(dataOfs[i]))
	}
	w.putU32(e32Ofs+0x54, uint32(headerSize)) // e32_hdrsize

	return w.buf, nil
}

// Sections Returns all program sections
func (m *Module) Sections() ([]Section, error) {
	secs := make([]Section, 0, len(m.O32s))
	var usage [len(segmentNames)]int

	for i, o := range m.O32s {
		kind := m.segmentKind(o)
		name := segmentNames[kind]
		if usage[kind] != 0 {
			name += fmt.Sprint(usage[kind])
		}
		usage[kind]++

		compressed := o.Flags&imageScnCompressed != 0
		off := m.ext.minusLoadOffset(o.DataPtr)
		data, err := m.ext.extractData(off, int64(min(o.VSize, o.PSize)), compressed, int64(o.VSize))
		if err != nil {
			return nil, fmt.Errorf("%s: section %d (%s): %w", m.Name, i, name, err)
		}
		secs = append(secs, Section{
			Index:       i,
			Name:        name,
			O32Rom:      o,
			Compressed:  compressed,
			ImageOffset: off,
			Data:        data,
		})
	}
	return secs, nil
}

// Module finds a module by name (case-insensitive).
func (e *Extractor) Module(name string) (*Module, bool) {
	for _, m := range e.Modules {
		if strings.EqualFold(m.Name, name) {
			return m, true
		}
	}
	return nil, false
}

// Bytes returns the whole WinCE image buffer, including any modifications made.
func (e *Extractor) Bytes() []byte { return e.image }

// WriteImage writes the whole WinCE image to w.
func (e *Extractor) WriteImage(w io.Writer) (int64, error) {
	n, err := w.Write(e.image)
	return int64(n), err
}

// SaveImage writes the whole WinCE image to a file.
func (e *Extractor) SaveImage(path string) error {
	return os.WriteFile(path, e.image, 0o644)
}

// sectionNames returns the PE-style names that Sections() assigns.
func (m *Module) sectionNames() []string {
	names := make([]string, len(m.O32s))
	var usage [len(segmentNames)]int
	for i, o := range m.O32s {
		k := m.segmentKind(o)
		n := segmentNames[k]
		if usage[k] != 0 {
			n += fmt.Sprint(usage[k])
		}
		usage[k]++
		names[i] = n
	}
	return names
}

// SectionIndex returns the index of the section with the given name (".text", ".data1", ...).
func (m *Module) SectionIndex(name string) (int, bool) {
	for i, n := range m.sectionNames() {
		if strings.EqualFold(n, name) {
			return i, true
		}
	}
	return 0, false
}

// ReplaceSection overwrites the stored bytes of section index with data, in
// place. data must have exactly the stored length (min(VSize, PSize)) and the
// section must not be compressed. Nothing else in the image is modified.
func (m *Module) ReplaceSection(index int, data []byte) error {
	if index < 0 || index >= len(m.O32s) {
		return ErrOutOfRange
	}
	o := m.O32s[index]
	stored := int64(min(o.VSize, o.PSize))
	if o.Flags&imageScnCompressed != 0 && stored != int64(o.VSize) {
		return fmt.Errorf("%s: section %d: %w", m.Name, index, ErrCompressedSection)
	}
	if int64(len(data)) != stored {
		return fmt.Errorf("%s: section %d: %w: got %d bytes, section stores %d",
			m.Name, index, ErrSizeMismatch, len(data), stored)
	}
	dst, err := m.ext.slice(m.ext.minusLoadOffset(o.DataPtr), stored)
	if err != nil {
		return fmt.Errorf("%s: section %d: %w", m.Name, index, err)
	}
	copy(dst, data)
	return nil
}

// ReplaceSectionByName is ReplaceSection addressed by section name.
func (m *Module) ReplaceSectionByName(name string, data []byte) error {
	i, ok := m.SectionIndex(name)
	if !ok {
		return fmt.Errorf("%s: section %q: %w", m.Name, name, ErrNotFound)
	}
	return m.ReplaceSection(i, data)
}

func (m *Module) segmentKind(o O32Rom) int {
	switch {
	case m.E32.Unit[unitRES].RVA == o.RVA && m.E32.Unit[unitRES].Size == o.VSize:
		return segRsrc
	case m.E32.Unit[unitEXC].RVA == o.RVA && m.E32.Unit[unitEXC].Size == o.VSize:
		return segPData
	case o.Flags&imageScnCntCode != 0:
		return segText
	case o.Flags&imageScnCntInitializedData != 0:
		return segData
	case o.Flags&imageScnCntUninitializedData != 0:
		return segPData
	default:
		return segOther
	}
}

func (m *Module) sumSegmentSizes(flag uint32) uint32 {
	var sum uint32
	for _, o := range m.O32s {
		if o.Flags&flag != 0 {
			sum += o.VSize
		}
	}
	return sum
}

func (m *Module) firstSegmentRVA(flag uint32) uint32 {
	for _, o := range m.O32s {
		if o.Flags&flag != 0 {
			return o.RVA
		}
	}
	return 0
}

// buildE32Header serializes a 248-byte PE signature + COFF header + optional
// header (with 16 data directories).
func (m *Module) buildE32Header() []byte {
	b := make([]byte, 248)
	p16 := func(off int, v uint16) { le.PutUint16(b[off:], v) }
	p32 := func(off int, v uint32) { le.PutUint32(b[off:], v) }

	copy(b[0:4], "PE\x00\x00")
	p16(4, m.rom.CPUType)
	p16(6, m.E32.ObjCnt)
	p32(8, uint32(m.Toc.FileTime.Unix()))
	// 12: symtaboff = 0, 16: symcount = 0
	p16(20, 0xe0) // opthdrsize
	p16(22, m.E32.ImageFlags|imageFileRelocsStripped)
	p16(24, 0x10b) // coffmagic
	b[26] = 6      // linkmajor
	b[27] = 1      // linkminor
	p32(28, m.sumSegmentSizes(imageScnCntCode))
	p32(32, m.sumSegmentSizes(imageScnCntInitializedData))
	p32(36, m.sumSegmentSizes(imageScnCntUninitializedData))
	p32(40, m.E32.EntryRVA)
	p32(44, m.firstSegmentRVA(imageScnCntCode))
	p32(48, m.firstSegmentRVA(imageScnCntInitializedData))
	p32(52, m.E32.VBase)
	p32(56, 0x1000) // objalign
	p32(60, 0x200)  // filealign
	p16(64, 4)      // osmajor
	p16(66, 0)      // osminor
	p16(72, m.E32.SubsysMajor)
	p16(74, m.E32.SubsysMinor)
	p32(80, m.E32.VSize)
	// 84: hdrsize (patched once the header size is known), 88: filechksum = 0
	p16(92, m.E32.Subsys)
	p32(96, m.E32.StackMax)
	p32(100, 0x1000)   // stackinit
	p32(104, 0x100000) // heapmax
	p32(108, 0x1000)   // heapinit
	p32(116, stdExtra) // hdrextra

	unit := func(idx int, in Info) {
		p32(120+8*idx, in.RVA)
		p32(124+8*idx, in.Size)
	}
	for _, idx := range []int{unitEXP, unitIMP, unitRES, unitEXC, unitSEC, unitIMD, unitMSP} {
		unit(idx, m.E32.Unit[idx])
	}
	unit(unitRS4, Info{RVA: m.E32.Sect14RVA, Size: m.E32.Sect14Size})
	return b
}

// buildO32Header serializes a 40-byte PE section header. usage tracks how many
// sections of each kind were already named so names stay unique.
func (m *Module) buildO32Header(o O32Rom, usage *[len(segmentNames)]int) []byte {
	var seg int
	switch {
	case m.E32.Unit[unitRES].RVA == o.RVA && m.E32.Unit[unitRES].Size == o.VSize:
		seg = segRsrc
	case m.E32.Unit[unitEXC].RVA == o.RVA && m.E32.Unit[unitEXC].Size == o.VSize:
		seg = segPData
	case o.Flags&imageScnCntCode != 0:
		seg = segText
	case o.Flags&imageScnCntInitializedData != 0:
		seg = segData
	case o.Flags&imageScnCntUninitializedData != 0:
		seg = segPData
	default:
		seg = segOther
	}

	name := segmentNames[seg]
	if usage[seg] != 0 {
		name += fmt.Sprint(usage[seg])
	}
	usage[seg]++

	b := make([]byte, 40)
	copy(b[0:e32ObjNameBytes], name) // truncated to 8 bytes, zero padded
	le.PutUint32(b[8:], o.VSize)
	le.PutUint32(b[12:], o.RealAddr-m.E32.VBase)
	// 16: psize, 20: dataptr (patched later), 24: realaddr, 28: access, 32: temp3 = 0
	le.PutUint32(b[36:], o.Flags&^imageScnCompressed)
	return b
}

// ---------------------------------------------------------------------------
// PE image writer
// ---------------------------------------------------------------------------

type imageWriter struct {
	buf []byte
}

func (w *imageWriter) len() int { return len(w.buf) }

func (w *imageWriter) write(b []byte) { w.buf = append(w.buf, b...) }

func (w *imageWriter) blanks(n int) { w.buf = append(w.buf, make([]byte, n)...) }

// align pads with zeros up to the next multiple of pageSize.
func (w *imageWriter) align(pageSize int) {
	if r := len(w.buf) % pageSize; r != 0 {
		w.blanks(pageSize - r)
	}
}

func (w *imageWriter) putU32(off int, v uint32) { le.PutUint32(w.buf[off:], v) }

// writeDummyMZHeader writes a 64-byte DOS header, the DOS stub message and
// padding, so the PE header lands at e_lfanew = 0xC0.
func (w *imageWriter) writeDummyMZHeader() {
	dos := make([]byte, 64)
	le.PutUint16(dos[0:], imageDOSSignature) // e_magic
	le.PutUint16(dos[2:], 0x90)              // e_cblp
	le.PutUint16(dos[4:], 3)                 // e_cp
	le.PutUint16(dos[8:], 0x4)               // e_cparhdr
	le.PutUint16(dos[12:], 0xffff)           // e_maxalloc
	le.PutUint16(dos[16:], 0xb8)             // e_sp
	le.PutUint16(dos[24:], 0x40)             // e_lfarlc
	le.PutUint32(dos[60:], 0xc0)             // e_lfanew

	doscode := []byte{
		0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
		0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
		0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
		0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	w.write(dos)
	w.write(doscode)
	w.blanks(0x40)
}
