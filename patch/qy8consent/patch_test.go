package qy8consent

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"LeafSDTools_Companion/patch/wince"
)

func TestInstructionEncoding(t *testing.T) {
	// Values come from ZE1's actual stock handler.
	const va = 0x41a0a5c0
	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"bl to GetContext", bl(va+0x00, 0x41b2f560), 0xeb0493e6},
		{"b to the tail", b(va+0x70, 0x41a0a680), 0xea000012},
		{"bne over the second dispatch", bne(va+0x54, va+0x68), 0x1a000003},
		{"movw of a composite action", movw(1, 4892), 0xe301131c},
		{"mov of a small variable id", movImm(1, 73), 0xe3a01049},
		{"mov with a rotated immediate", movImm(1, 628), 0xe3a01f9d},
		{"movw where mov cannot reach", movImm(1, 1687), 0xe3001697},
		{"ldr from the literal pool", ldrPC(va+0x04, 2, 0x41a0a690), 0xe59f20c4},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: got 0x%08x, want 0x%08x", tt.name, tt.got, tt.want)
		}
	}
}

func TestDecodeInversesEncode(t *testing.T) {
	const at = 0x41a0a5c0
	for _, to := range []uint32{0x41b2f560, 0x418b6488, 0x41000000} {
		if got, ok := decodeBL(at, bl(at, to)); !ok || got != to {
			t.Errorf("decodeBL(bl(at,0x%x)) = 0x%x,%v", to, got, ok)
		}
		if got, ok := decodeB(at, b(at, to)); !ok || got != to {
			t.Errorf("decodeB(b(at,0x%x)) = 0x%x,%v", to, got, ok)
		}
	}
	if _, ok := decodeBL(at, 0xe58d00d4); ok {
		t.Error("decodeBL accepted a str instruction")
	}
	for _, imm := range []uint32{0, 25, 47, 73, 223, 257, 628} {
		w := movImm(1, imm)
		if w>>24 == 0xe3 && w&0xfff00000 == 0xe3a00000 { // only check the mov form here; movw is checked below
			got, ok := decodeMovImm(w, 1)
			if !ok || got != imm {
				t.Errorf("decodeMovImm(movImm(1,%d)) = %d,%v", imm, got, ok)
			}
		}
	}
	for _, imm := range []uint32{1609, 1611, 1687, 4676, 4892} {
		w := movw(2, imm)
		got, ok := decodeMovw(w, 2)
		if !ok || got != imm {
			t.Errorf("decodeMovw(movw(2,%d)) = %d,%v", imm, got, ok)
		}
		if _, ok := decodeMovw(w, 1); ok {
			t.Errorf("decodeMovw matched the wrong register for movw(2,%d)", imm)
		}
	}
}

func TestWordSum(t *testing.T) {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:], 0xffffffff)
	binary.LittleEndian.PutUint32(b[4:], 2)
	binary.LittleEndian.PutUint32(b[8:], 0x10000000)
	if got := wordSum(b); got != 0x10000001 {
		t.Errorf("wordSum = 0x%08x, want 0x10000001 (it has to wrap)", got)
	}
	if got := wordSum(b[:3]); got != 0 {
		t.Errorf("wordSum of a partial word = 0x%08x, want 0", got)
	}
}

func TestDiffPagesStaysInRange(t *testing.T) {
	const base = 0x200000 + 123
	before := make([]byte, 3*pageSize+100)
	mod := bytes.Clone(before)
	mod[50] = 1
	mod[pageSize+10] = 1
	mod[len(mod)-1] = 1

	writes := diffPages(before, mod, base)
	if len(writes) != 3 {
		t.Fatalf("got %d page writes, want 3", len(writes))
	}
	lo, hi := int64(base), int64(base+len(mod))
	for _, w := range writes {
		if w.Offset < lo || w.Offset+int64(len(w.Data)) > hi {
			t.Errorf("write at 0x%x, %d bytes, falls outside 0x%x-0x%x", w.Offset, len(w.Data), lo, hi)
		}
	}
}

// buildWords fills stockPattern's wildcarded bits from a seed, so it matches
// stockMask/stockPattern without being the literal pattern (which would pass trivially).
func buildWords(seed uint32) []uint32 {
	out := make([]uint32, len(stockPattern))
	for i, p := range stockPattern {
		out[i] = p | (seed+uint32(i))&^stockMask[i]
	}
	return out
}

func wordsToBytes(words []uint32) []byte {
	b := make([]byte, 4*len(words))
	for i, w := range words {
		binary.LittleEndian.PutUint32(b[i*4:], w)
	}
	return b
}

func TestFindMasked(t *testing.T) {
	code := make([]byte, 4096)
	copy(code[1000:], wordsToBytes(buildWords(0xabc)))

	hits := findMasked(code, stockMask[:], stockPattern[:])
	if len(hits) != 1 || hits[0] != 1000 {
		t.Fatalf("findMasked hits = %v, want [1000]", hits)
	}
}

func TestFindMaskedRejectsAFixedBitMismatch(t *testing.T) {
	code := make([]byte, 4096)
	words := buildWords(0xabc)
	words[16] ^= 1 // flip a bit inside stockMask[16], which is fully fixed (cmp r3,#0)
	copy(code[1000:], wordsToBytes(words))

	if hits := findMasked(code, stockMask[:], stockPattern[:]); len(hits) != 0 {
		t.Errorf("findMasked matched a handler with a changed fixed bit: %v", hits)
	}
}

func TestFindPatchedSig(t *testing.T) {
	code := make([]byte, 256)
	binary.LittleEndian.PutUint32(code[40:], patchedSig[0])
	binary.LittleEndian.PutUint32(code[44:], patchedSig[1])
	binary.LittleEndian.PutUint32(code[40+6*4:], patchedSig[2])
	binary.LittleEndian.PutUint32(code[40+7*4:], patchedSig[3])
	if !findPatchedSig(code) {
		t.Error("findPatchedSig missed a planted already-patched signature")
	}
	if findPatchedSig(make([]byte, 256)) {
		t.Error("findPatchedSig matched an all-zero buffer")
	}
}

func TestFindNamesWhateverSitsAtAnMTCPSegment(t *testing.T) {
	img := make([]byte, 4<<20)
	at := 0x200000
	copy(img[at+offName:], "G214ELNI.999")
	copy(img[at+segOffset:], "MTCP")
	binary.LittleEndian.PutUint32(img[at+offPayloadLen:], 123)

	got, err := Find(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.Offset != int64(at) {
		t.Errorf("found the nav image at 0x%x, want 0x%x", got.Offset, at)
	}
	if got.Build != "G214ELNI.999" {
		t.Errorf("build %q, want %q", got.Build, "G214ELNI.999")
	}
}

func TestFindReportsNothingOnAnEmptyCard(t *testing.T) {
	img := make([]byte, 3<<20)
	if _, err := Find(bytes.NewReader(img), int64(len(img))); err == nil {
		t.Error("Find claimed to see a nav image in an empty card")
	}
}

func TestFindStopsAtTheGivenLimit(t *testing.T) {
	const limit = 1 << 20
	img := make([]byte, 6<<20)
	const plantedAt = 4 << 20
	copy(img[plantedAt+offName:], "G214ELNI.062")
	copy(img[plantedAt+segOffset:], "MTCP")
	binary.LittleEndian.PutUint32(img[plantedAt+offPayloadLen:], 123)

	if _, err := Find(bytes.NewReader(img), limit); err == nil {
		t.Error("Find saw a name planted past the given limit")
	}
	got, err := Find(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatalf("Find over the whole image: %v", err)
	}
	if got.Offset != plantedAt {
		t.Errorf("found the nav image at 0x%x, want 0x%x", got.Offset, plantedAt)
	}
}

type memRWAt struct{ b []byte }

func (m *memRWAt) ReadAt(p []byte, off int64) (int, error) {
	return bytes.NewReader(m.b).ReadAt(p, off)
}
func (m *memRWAt) WriteAt(p []byte, off int64) (int, error) {
	copy(m.b[off:], p)
	return len(p), nil
}
func (m *memRWAt) Sync() error { return nil }

type faultRWAt struct {
	b      []byte
	writes int
	failAt int
	failed bool
	syncs  int
	direct bool
}

func (f *faultRWAt) ReadAt(p []byte, off int64) (int, error) {
	if f.direct {
		if off%directAlign != 0 || len(p)%directAlign != 0 || uintptr(unsafe.Pointer(&p[0]))%directAlign != 0 {
			return 0, fmt.Errorf("unaligned read")
		}
	}
	return bytes.NewReader(f.b).ReadAt(p, off)
}

func (f *faultRWAt) WriteAt(p []byte, off int64) (int, error) {
	if f.direct {
		if off%directAlign != 0 || len(p)%directAlign != 0 || uintptr(unsafe.Pointer(&p[0]))%directAlign != 0 {
			return 0, fmt.Errorf("unaligned write")
		}
	}
	f.writes++
	if !f.failed && f.failAt > 0 && f.writes == f.failAt {
		f.failed = true
		return 0, fmt.Errorf("injected write failure")
	}
	if off < 0 || off+int64(len(p)) > int64(len(f.b)) {
		return 0, io.ErrShortWrite
	}
	copy(f.b[off:], p)
	return len(p), nil
}

func (f *faultRWAt) Sync() error    { f.syncs++; return nil }
func (f *faultRWAt) DirectIO() bool { return f.direct }

func syntheticPlan(original []byte) ([]byte, []PageWrite) {
	planned := bytes.Clone(original)
	planned[segOffset+offReserved] = 0x44
	planned[pageSize+37] = 0x55
	planned[2*pageSize+91] = 0x66
	writes := diffPages(original, planned, 0)
	orderWrites(writes, segOffset)
	return planned, writes
}

func TestSyntheticPlanApplyVerify(t *testing.T) {
	original := make([]byte, 3*pageSize)
	planned, writes := syntheticPlan(original)
	f := &faultRWAt{b: bytes.Clone(original)}
	if err := applyAndVerify(f, Target{Size: len(original)}, original, writes); err != nil {
		t.Fatalf("applyAndVerify: %v", err)
	}
	if !bytes.Equal(f.b, planned) {
		t.Error("applied bytes differ from the plan")
	}
	if f.syncs != 1 {
		t.Errorf("Sync called %d times, want 1", f.syncs)
	}
}

func TestWriteFailureRestoresOriginal(t *testing.T) {
	original := bytes.Repeat([]byte{0xa5}, 3*pageSize)
	_, writes := syntheticPlan(original)
	f := &faultRWAt{b: bytes.Clone(original), failAt: 2}
	err := applyAndVerify(f, Target{Size: len(original)}, original, writes)
	if err == nil || !strings.Contains(err.Error(), "restored successfully") {
		t.Fatalf("error does not report successful restore: %v", err)
	}
	if !bytes.Equal(f.b, original) {
		t.Error("rollback did not restore the original bytes exactly")
	}
}

func TestForgedSizesReturnErrors(t *testing.T) {
	if _, err := checkedContainerSize(^uint32(0), 0, 0); err == nil {
		t.Error("accepted an oversized container")
	}
	mod := make([]byte, 2*sectorSize)
	copy(mod[segOffset:], "MTCP")
	binary.LittleEndian.PutUint32(mod[segOffset+offChunkCnt:], 1)
	e := mod[segOffset+offChunkEnts:]
	binary.LittleEndian.PutUint32(e[0:], 1)
	binary.LittleEndian.PutUint32(e[4:], 32)
	binary.LittleEndian.PutUint32(e[8:], sectorSize+1)
	if _, err := chunks(mod); err == nil {
		t.Error("accepted a packed chunk larger than its sector extent")
	}
}

func TestDirectIOFindUsesAlignedRequests(t *testing.T) {
	img := make([]byte, 4<<20)
	const at = 2 << 20
	copy(img[at+offName:], "G214ELNI.999")
	copy(img[at+segOffset:], "MTCP")
	binary.LittleEndian.PutUint32(img[at+offPayloadLen:], sectorSize)
	f := &faultRWAt{b: img, direct: true}
	got, err := Find(f, int64(len(img)))
	if err != nil {
		t.Fatalf("Find through direct I/O: %v", err)
	}
	if got.Offset != at {
		t.Errorf("offset = 0x%x, want 0x%x", got.Offset, at)
	}
}

func TestDirectIOApplyUsesAlignedRequests(t *testing.T) {
	original := bytes.Repeat([]byte{0x31}, 3*pageSize)
	f := &faultRWAt{b: bytes.Clone(original), direct: true}
	dev := directReadWriter(f, int64(len(original)))
	want := bytes.Repeat([]byte{0x72}, 173)
	writes := []PageWrite{{Offset: 123, Data: want}}
	if err := applyAndVerify(dev, Target{Size: len(original)}, original, writes); err != nil {
		t.Fatalf("apply through direct I/O: %v", err)
	}
	if !bytes.Equal(f.b[123:123+len(want)], want) {
		t.Error("unaligned planned range was not applied")
	}
}

// QY8_ZE0_MOD / QY8_ME0_MOD: stock .mod from ProbeOffset. QY8_ZE1_PATCHED_MOD: already patched.
// Skipped when the env var is unset. No stock ZE1 sample exists, so ZE1 only gets the already-patched check.

func readFixture(t *testing.T, envVar string) []byte {
	t.Helper()
	path := os.Getenv(envVar)
	if path == "" {
		t.Skipf("%s not set; skipping (see the comment above this test)", envVar)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("%s=%s: %v", envVar, path, err)
	}
	return data
}

func patchCopy(t *testing.T, data []byte) ([]byte, Result, error) {
	t.Helper()
	cp := bytes.Clone(data)
	f := &memRWAt{cp}
	res, err := ApplyConsentSkip(f, int64(len(cp)), func(s string) { t.Log(s) })
	return cp, res, err
}

func TestZE0MatchesTheReferencePatcher(t *testing.T) {
	data := readFixture(t, "QY8_ZE0_MOD")
	out, _, err := patchCopy(t, data)
	if err != nil {
		t.Fatalf("ApplyConsentSkip: %v", err)
	}
	// Reference output must stay byte-identical.
	const want = "ad998ae9e47483ff8382926a91e88a9a20614ca0e12ac0b3620325689ae24444"
	if got := sha256hex(out); got != want {
		t.Errorf("ZE0 .062 patched sha256 = %s, want %s (not byte-identical to the reference patcher)", got, want)
	}
}

func TestME0MatchesTheKnownGoodHash(t *testing.T) {
	data := readFixture(t, "QY8_ME0_MOD")
	out, _, err := patchCopy(t, data)
	if err != nil {
		t.Fatalf("ApplyConsentSkip: %v", err)
	}
	const want = "bcf0153a05953ce1c54fa9fcb187c9f0af9f671df3826561d9cdc6af68ccd9c7"
	if got := sha256hex(out); got != want {
		t.Errorf("ME0 .017 patched sha256 = %s, want %s", got, want)
	}
}

func TestZE1AlreadyPatchedIsLeftAlone(t *testing.T) {
	data := readFixture(t, "QY8_ZE1_PATCHED_MOD")
	out, _, err := patchCopy(t, data)
	if err == nil {
		t.Fatal("patched an image this package should recognise as already done")
	}
	if !strings.Contains(err.Error(), "already patched") {
		t.Errorf("error doesn't say already patched: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Error("the image was modified despite the refusal")
	}
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var derivationFixtures = map[string][3]uint32{
	"G214ELNI.062": {223, 563, 1609},
	"G218ENNI.120": {257, 628, 1687},
	"G214ELNI.017": {224, 565, 1611},
	"G214ELNI.066": {224, 564, 1609},
	"G214ELNI.112": {224, 565, 1609},
}

func fixtureImages(t *testing.T) map[string][]byte {
	t.Helper()
	dir := os.Getenv("QY8_FIXTURE_DIR")
	if dir == "" {
		t.Skip("QY8_FIXTURE_DIR not set")
	}
	paths, err := filepath.Glob(filepath.Join(dir, "nand-*.mod"))
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string][]byte)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			continue
		}
		if len(data) < offName+16 {
			continue
		}
		name, err := readName(data[:offSegTable])
		if err == nil {
			if _, wanted := derivationFixtures[name]; wanted {
				out[name] = data
			}
		}
	}
	if len(out) == 0 {
		t.Skipf("no QY8 fixtures in %s", dir)
	}
	return out
}

func fixtureROM(t *testing.T, mod []byte) ([]byte, []byte) {
	t.Helper()
	cs, err := chunks(mod)
	if err != nil {
		t.Fatal(err)
	}
	seg0, _, err := decompressAll(mod, cs)
	if err != nil {
		t.Fatal(err)
	}
	end := cs[len(cs)-1].at + cs[len(cs)-1].sectors*sectorSize
	rom := append(bytes.Clone(seg0), mod[end:]...)
	return seg0, rom
}

func screenStateSections(t *testing.T, rom []byte) []moduleSection {
	t.Helper()
	ex, err := wince.NewExtractorAt(rom, 0)
	if err != nil {
		ex, err = wince.NewExtractor(rom)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ex.Modules {
		if m.Name == "ScreenStateCC.dll" {
			sections, err := moduleSections(m)
			if err != nil {
				t.Fatal(err)
			}
			return sections
		}
	}
	t.Fatal("ScreenStateCC.dll not found")
	return nil
}

func TestNameRankDerivation(t *testing.T) {
	for name, mod := range fixtureImages(t) {
		t.Run(name, func(t *testing.T) {
			_, rom := fixtureROM(t, mod)
			sections := screenStateSections(t, rom)
			want := derivationFixtures[name]
			for i, variable := range []string{"VAR_I_AGREE_STATUS", "VAR_START_UP_I_AGREE_STATUS", "TELEMA_NOTIFY_AGREE"} {
				got, err := nameRank(sections, variable)
				if err != nil {
					t.Fatal(err)
				}
				if got != want[i] {
					t.Errorf("%s rank = %d, want %d", variable, got, want[i])
				}
			}
		})
	}
}

func TestFullDerivation(t *testing.T) {
	for name, mod := range fixtureImages(t) {
		t.Run(name, func(t *testing.T) {
			seg0, rom := fixtureROM(t, mod)
			d, err := derive(seg0, rom)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(skipBody(d)); got != 29 {
				t.Fatalf("patch body has %d words", got)
			}
			want := derivationFixtures[name]
			got := [3]uint32{d.VarAgree, d.VarStartup, d.Notify}
			t.Logf("%s: varAgree=%d varStartup=%d notify=%d", name, got[0], got[1], got[2])
			if got != want {
				t.Errorf("derived values = %v, want %v", got, want)
			}
		})
	}
}
