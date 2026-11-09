// Package qy8consent skips the telematics consent screen on a Clarion QY8 nav image.
//
// The .mod header must stay byte-identical or the loader won't boot the card's NK2.
package qy8consent

import (
	"LeafSDTools_Companion/patch"
	"LeafSDTools_Companion/patch/common"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"

	"LeafSDTools_Companion/patch/qy8consent/lz4hc"
)

const (
	pageSize         = 4096
	maxContainerSize = 256 << 20
	maxUnpackedSize  = 512 << 20
)

type Target struct {
	Offset int64
	Build  string
	Size   int
}

type Result struct {
	Target       Target
	Chunk        int
	Stock        int
	Packed       int
	Room         int
	Compensation uint32
	Pages        int
	SHA256       string
}

// ProbeOffset is where the nav image sits on every ZE0, ZE1 and ME0 card seen.
const ProbeOffset = 0x4d00000

func Find(f io.ReaderAt, size int64) (Target, error) {
	f = patcher_common.DirectReader(f, size)
	if t, found, err := probeFixed(f, size); found {
		return t, err
	}
	return findBySignature(f, size)
}

// probeFixed checks ProbeOffset before scanning the whole device; a readable
// name at an MTCP segment there is enough, even for an unknown build.
func probeFixed(f io.ReaderAt, size int64) (Target, bool, error) {
	hdr := make([]byte, offSegTable)
	if _, err := f.ReadAt(hdr, ProbeOffset); err != nil {
		return Target{}, false, err
	}
	name, err := readName(hdr)
	if err != nil {
		return Target{}, false, err
	}
	magic := make([]byte, 4)
	if _, err := f.ReadAt(magic, ProbeOffset+segOffset); err != nil || string(magic) != "MTCP" {
		return Target{}, false, fmt.Errorf("no MTCP segment where the probe expects one")
	}
	modLen, err := checkedContainerSize(binary.LittleEndian.Uint32(hdr[offPayloadLen:]), ProbeOffset, size)
	if err != nil {
		return Target{}, true, err
	}
	return Target{Offset: ProbeOffset, Build: name, Size: modLen}, true, nil
}

func checkedContainerSize(payload uint32, offset, deviceSize int64) (int, error) {
	total := int64(payload) + segOffset
	if total < segOffset || total > maxContainerSize {
		return 0, fmt.Errorf("container size %d exceeds the 256 MiB cap", total)
	}
	if deviceSize > 0 && (offset < 0 || offset > deviceSize || total > deviceSize-offset) {
		return 0, fmt.Errorf("container at 0x%x, size %d exceeds device size %d", offset, total, deviceSize)
	}
	return int(total), nil
}

func readName(hdr []byte) (string, error) {
	nameField := hdr[offName:]
	if nul := bytes.IndexByte(nameField, 0); nul >= 0 {
		nameField = nameField[:nul]
	}
	if len(nameField) == 0 {
		return "", fmt.Errorf("empty name field")
	}
	return string(nameField), nil
}

// findBySignature falls back to the MTCP marker for an offset the probe missed.
func findBySignature(f io.ReaderAt, size int64) (Target, error) {
	const step = 1 << 20
	buf := make([]byte, step+sectorSize)
	var candidateErr error
	for off := int64(0); size <= 0 || off < size; off += step {
		n, err := f.ReadAt(buf, off)
		blk := buf[:max(n, 0)]
		for i := 0; i < len(blk); {
			j := bytes.Index(blk[i:], []byte("MTCP"))
			if j < 0 {
				break
			}
			i += j
			at := off + int64(i) - segOffset
			i++
			if at < 0 || at%sectorSize != 0 {
				continue
			}
			hdr := make([]byte, offSegTable)
			if _, herr := f.ReadAt(hdr, at); herr != nil {
				continue
			}
			name, nerr := readName(hdr)
			if nerr != nil {
				continue
			}
			modLen, serr := checkedContainerSize(binary.LittleEndian.Uint32(hdr[offPayloadLen:]), at, size)
			if serr != nil {
				candidateErr = serr
				continue
			}
			return Target{Offset: at, Build: name, Size: modLen}, nil
		}
		if err != nil {
			break
		}
	}
	if candidateErr != nil {
		return Target{}, candidateErr
	}
	return Target{}, fmt.Errorf("no nav image found on that target")
}

type PageWrite struct {
	Offset int64
	Data   []byte
}

func planConsentSkip(f io.ReaderAt, size int64, log func(string)) (Result, []PageWrite, error) {
	f = patcher_common.DirectReader(f, size)
	t, err := Find(f, size)
	if err != nil {
		return Result{}, nil, err
	}
	if t.Offset != ProbeOffset {
		log(fmt.Sprintf("Nav image not at the usual offset; found it by scanning, at 0x%x", t.Offset))
	}
	log(fmt.Sprintf("Found %s at 0x%x, %d bytes", t.Build, t.Offset, t.Size))

	mod := make([]byte, t.Size)
	if _, err := f.ReadAt(mod, t.Offset); err != nil && err != io.EOF {
		return Result{}, nil, fmt.Errorf("cannot read the nav image: %w", err)
	}
	before := bytes.Clone(mod)

	res, err := patchMod(mod, t.Build, log)
	if err != nil {
		return Result{}, nil, err
	}
	res.Target = t

	writes := diffPages(before, mod, t.Offset)
	res.Pages = len(writes)

	sum := sha256.Sum256(mod)
	res.SHA256 = hex.EncodeToString(sum[:])
	return res, writes, nil
}

// diffPages keeps every write inside [base, base+len(mod)), the .mod
// container the two came from.
func diffPages(before, mod []byte, base int64) []PageWrite {
	var writes []PageWrite
	for abs := base / pageSize * pageSize; abs < base+int64(len(mod)); abs += pageSize {
		lo := max(abs, base) - base
		hi := min(abs+pageSize, base+int64(len(mod))) - base
		if bytes.Equal(mod[lo:hi], before[lo:hi]) {
			continue
		}
		writes = append(writes, PageWrite{Offset: base + lo, Data: bytes.Clone(mod[lo:hi])})
	}
	return writes
}

// ApplyConsentSkip writes only after PlanConsentSkip finds exactly one handler match.
func applyConsentSkip(f patch.ReadWriterAt, size int64, log func(string)) error {
	dev := patcher_common.DirectReadWriter(f, size)
	res, writes, err := planConsentSkip(dev, size, log)
	if err != nil {
		return err
	}
	original := make([]byte, res.Target.Size)
	if err := readFullAt(dev, original, res.Target.Offset); err != nil {
		return fmt.Errorf("cannot preserve the nav image: %w", err)
	}

	// Payload first keeps the old MTCP lengths and checksums valid longest.
	orderWrites(writes, res.Target.Offset+segOffset)
	if err := applyAndVerify(dev, res.Target, original, writes); err != nil {
		return err
	}
	log(fmt.Sprintf("Wrote %d pages of 4 KiB", res.Pages))
	log("Nav image sha256: " + res.SHA256)
	log(fmt.Sprintf("Patched %s, chunk %d (%d -> %d bytes).", res.Target.Build, res.Chunk, res.Stock, res.Packed))
	return nil
}

func orderWrites(writes []PageWrite, metadata int64) {
	sort.SliceStable(writes, func(i, j int) bool {
		iMeta := writes[i].Offset <= metadata && metadata < writes[i].Offset+int64(len(writes[i].Data))
		jMeta := writes[j].Offset <= metadata && metadata < writes[j].Offset+int64(len(writes[j].Data))
		return !iMeta && jMeta
	})
}

func applyAndVerify(f patch.ReadWriterAt, target Target, original []byte, writes []PageWrite) error {
	failure := func(cause error) error {
		restoreErr := writeFullAt(f, original, target.Offset)
		if restoreErr == nil {
			restoreErr = syncAndVerify(f, target.Offset, original)
		}
		if restoreErr != nil {
			return fmt.Errorf("%w; restore failed: %v", cause, restoreErr)
		}
		return fmt.Errorf("%w; original bytes restored successfully", cause)
	}

	for _, w := range writes {
		if err := writeFullAt(f, w.Data, w.Offset); err != nil {
			return failure(fmt.Errorf("cannot write at 0x%x: %w", w.Offset, err))
		}
	}
	s, ok := f.(patcher_common.Syncer)
	if !ok {
		return failure(fmt.Errorf("target does not support sync"))
	}
	if err := s.Sync(); err != nil {
		return failure(fmt.Errorf("cannot sync patched bytes: %w", err))
	}
	for _, w := range writes {
		got := make([]byte, len(w.Data))
		if err := readFullAt(f, got, w.Offset); err != nil {
			return failure(fmt.Errorf("cannot verify at 0x%x: %w", w.Offset, err))
		}
		if !bytes.Equal(got, w.Data) {
			return failure(fmt.Errorf("verification mismatch at 0x%x", w.Offset))
		}
	}
	return nil
}

func syncAndVerify(f patch.ReadWriterAt, off int64, want []byte) error {
	s, ok := f.(patcher_common.Syncer)
	if !ok {
		return fmt.Errorf("target does not support sync")
	}
	if err := s.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	got := make([]byte, len(want))
	if err := readFullAt(f, got, off); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("verify mismatch")
	}
	return nil
}

func readFullAt(f io.ReaderAt, p []byte, off int64) error {
	n, err := f.ReadAt(p, off)
	if n != len(p) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}

func writeFullAt(f io.WriterAt, p []byte, off int64) error {
	n, err := f.WriteAt(p, off)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

func patchMod(mod []byte, name string, log func(string)) (Result, error) {
	if len(mod) < segOffset+sectorSize {
		return Result{}, fmt.Errorf("container is too small")
	}
	if got := int(binary.LittleEndian.Uint32(mod[offPayloadLen:])) + segOffset; got != len(mod) {
		return Result{}, fmt.Errorf("container claims %d bytes, read %d", got, len(mod))
	}
	header := bytes.Clone(mod[:segOffset])

	seg := mod[offSegTable:]
	segLen := int64(binary.LittleEndian.Uint32(seg[8:]))
	segSum := binary.LittleEndian.Uint32(seg[12:])
	if segLen < sectorSize || segLen > int64(len(mod)-segOffset) {
		return Result{}, fmt.Errorf("segment 0 runs past the container")
	}
	segEnd := segOffset + int(segLen)
	if got := wordSum(mod[segOffset:segEnd]); got != segSum {
		return Result{}, fmt.Errorf("segment 0 sum is 0x%08x, header says 0x%08x", got, segSum)
	}

	cs, err := chunks(mod)
	if err != nil {
		return Result{}, err
	}

	seg0, chunkPlain, err := decompressAll(mod, cs)
	if err != nil {
		return Result{}, err
	}
	more, segsEnd, err := nextSegments(mod, cs)
	if err != nil {
		return Result{}, err
	}
	rom := make([]byte, 0, len(seg0)+len(more)+len(mod)-segsEnd)
	rom = append(rom, seg0...)
	rom = append(rom, more...)
	rom = append(rom, mod[segsEnd:]...)

	d, err := derive(seg0, rom)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", name, err)
	}
	log(fmt.Sprintf("Handler at 0x%08x (ScreenStateCC.dll code 0x%x, rom 0x%x)", d.SkipVA, d.CodeVA, d.CodeROM))

	if d.SkipVA < d.CodeVA {
		return Result{}, fmt.Errorf("handler address precedes its code section")
	}
	romOff := d.CodeROM + int(d.SkipVA-d.CodeVA)
	i := -1
	for n, c := range cs {
		if romOff >= c.plainAt && romOff < c.plainAt+c.plain {
			i = n
			break
		}
	}
	if i < 0 {
		return Result{}, fmt.Errorf("handler at 0x%x is not in any chunk", d.SkipVA)
	}
	c := cs[i]
	at := romOff - c.plainAt
	plain := chunkPlain[i]
	body := skipBody(d)
	if at < 0 || at > len(plain)-len(body)*4 {
		return Result{}, fmt.Errorf("handler body runs past chunk %d", i)
	}
	log(fmt.Sprintf("Handler is chunk %d +0x%x", i, at))

	putWords(plain[at:], body)

	packed := lz4hc.Compress(plain)
	back, err := lz4hc.Uncompress(packed, len(plain))
	if err != nil || !bytes.Equal(back, plain) {
		return Result{}, fmt.Errorf("recompressed chunk %d does not round-trip", i)
	}
	room := c.sectors * sectorSize
	log(fmt.Sprintf("Chunk %d: %d -> %d bytes, sectors hold %d, %d spare",
		i, c.packed, len(packed), room, room-len(packed)))
	if len(packed) > room {
		return Result{}, fmt.Errorf("patched chunk %d is %d bytes over its sectors", i, len(packed)-room)
	}

	res := Result{Chunk: i, Stock: c.packed, Packed: len(packed), Room: room}
	writeChunk(mod, cs, i, packed)

	// The loader's sum skips the tail padding, so the drift goes in this reserved word instead.
	pad := mod[segOffset+offReserved:]
	if binary.LittleEndian.Uint32(pad) != 0 {
		return res, fmt.Errorf("the reserved word in segment 0 is not zero")
	}
	drift := segSum - wordSum(mod[segOffset:segEnd])
	binary.LittleEndian.PutUint32(pad, drift)
	res.Compensation = drift
	log(fmt.Sprintf("Compensating word 0x%08x at .mod +0x%x", drift, segOffset+offReserved))

	if got := wordSum(mod[segOffset:segEnd]); got != segSum {
		return res, fmt.Errorf("segment 0 sum drifted to 0x%08x", got)
	}
	if got := loaderSum(mod, cs); got != segSum {
		return res, fmt.Errorf("the loader's sum drifted to 0x%08x", got)
	}
	if got, want := wordSum(mod[segOffset:]), binary.LittleEndian.Uint32(mod[offSum4:]); got != want {
		return res, fmt.Errorf("SUM4 is 0x%08x, header says 0x%08x", got, want)
	}
	if !bytes.Equal(mod[:segOffset], header) {
		return res, fmt.Errorf("the 512-byte header changed")
	}
	return res, nil
}

// decompressAll decompresses every segment-0 chunk, returning the concatenated
// plaintext for the extractor plus each chunk's own so none is decompressed twice.
func decompressAll(mod []byte, cs []chunk) ([]byte, [][]byte, error) {
	plains := make([][]byte, len(cs))
	var total []byte
	for i, c := range cs {
		p, err := lz4hc.Uncompress(mod[c.at:c.at+c.packed], c.plain)
		if err != nil {
			return nil, nil, fmt.Errorf("chunk %d: %w", i, err)
		}
		plains[i] = p
		total = append(total, p...)
	}
	return total, plains, nil
}

func putWords(b []byte, words []uint32) {
	for i, w := range words {
		binary.LittleEndian.PutUint32(b[i*4:], w)
	}
}

// skipBody is SK_CWS_AGREE_EXECUTE rewritten to skip the consent screen and
// notify Telema directly: 29 instructions in, 29 out, so it always fits.
func skipBody(d Derived) []uint32 {
	const ctrl = 25
	a := d.SkipVA
	done := a + 0x68
	return []uint32{
		bl(a+0x00, d.GetContext),
		ldrPC(a+0x04, 2, d.PTrue),
		movImm(1, d.VarSkip),
		bl(a+0x0c, d.SetVar),
		bl(a+0x10, d.GetContext),
		ldrPC(a+0x14, 2, d.PTrue),
		movImm(1, d.VarAgree),
		bl(a+0x1c, d.SetVar),
		bl(a+0x20, d.GetContext),
		ldrPC(a+0x24, 2, d.PTrue),
		movImm(1, d.VarStartup),
		bl(a+0x2c, d.SetVar),
		bl(a+0x30, d.GetContext),
		movw(2, d.Notify),
		movImm(1, ctrl),
		bl(a+0x3c, d.ExecFn),
		bl(a+0x40, d.GetContext),
		bl(a+0x44, d.GetState),
		movw(1, d.Action),
		bl(a+0x4c, d.EvHandler),
		0xe3500000,
		bne(a+0x54, done),
		bl(a+0x58, d.GetContext),
		bl(a+0x5c, d.GetState2),
		movw(1, d.Action),
		bl(a+0x64, d.EvHandler),
		0xe3a03001,
		0xe58d3000,
		b(a+0x70, d.Tail),
	}
}

// IMPL BasePatch

//go:embed qy8preview.jpg
var previewImg []byte

var PatchImpl = &patch.Patch{
	PatchName:  "Remove consent screen on QY8XXX (AZE0, ZE1, E-NV200, Japanese cards too)",
	PatchImage: &previewImg,
	Patcher:    applyConsentSkip,
	MediaType:  patch.MediaTypeSD,
}
