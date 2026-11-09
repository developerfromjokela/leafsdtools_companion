package qy8consent

import (
	"bytes"
	"encoding/binary"
	"testing"

	"LeafSDTools_Companion/patch/qy8consent/lz4hc"
)

// packContainer builds a minimal .mod container: a header, and one MTCP
// metadata sector per segment with its chunk data right behind it.
func packContainer(t *testing.T, segs [][]([]byte)) []byte {
	t.Helper()
	mod := make([]byte, segOffset)
	copy(mod[offName:], "G218ENNI.999")
	copy(mod[0x30:], "SUM4")

	pos := segOffset
	starts := make([]int, len(segs))
	ends := make([]int, len(segs))
	for si, chunks := range segs {
		if len(chunks) > maxChunks {
			t.Fatalf("segment %d has %d chunks, over the sector's %d", si, len(chunks), maxChunks)
		}
		starts[si] = pos
		if len(mod) < pos+sectorSize {
			mod = append(mod, make([]byte, pos+sectorSize-len(mod))...)
		}
		table := pos
		copy(mod[table:], "MTCP")
		binary.LittleEndian.PutUint32(mod[table+offChunkCnt:], uint32(len(chunks)))
		pos += sectorSize
		for ci, plain := range chunks {
			packed := lz4hc.Compress(plain)
			sectors := (len(packed) + sectorSize - 1) / sectorSize
			room := sectors * sectorSize
			mod = append(mod, packed...)
			mod = append(mod, make([]byte, room-len(packed))...)
			e := mod[table+offChunkEnts+ci*chunkEntSize:]
			binary.LittleEndian.PutUint32(e[0:], uint32(sectors))
			binary.LittleEndian.PutUint32(e[4:], uint32(len(plain)))
			binary.LittleEndian.PutUint32(e[8:], uint32(len(packed)))
			binary.LittleEndian.PutUint32(e[12:], wordSum(mod[pos:pos+room]))
			pos += room
		}
		ends[si] = pos
	}

	// Segment 0 is what the patcher reads out of the header's segment table.
	binary.LittleEndian.PutUint32(mod[offSegTable+8:], uint32(ends[0]-segOffset))
	binary.LittleEndian.PutUint32(mod[offSegTable+12:], wordSum(mod[segOffset:ends[0]]))
	binary.LittleEndian.PutUint32(mod[offPayloadLen:], uint32(len(mod)-segOffset))
	binary.LittleEndian.PutUint32(mod[offSum4:], wordSum(mod[segOffset:]))
	return mod
}

func TestContainerWithAFullChunkTable(t *testing.T) {
	var chunkPlains [][]byte
	for i := 0; i < maxChunks; i++ {
		chunkPlains = append(chunkPlains, bytes.Repeat([]byte{byte(i + 1)}, 0x1234))
	}
	mod := packContainer(t, [][][]byte{chunkPlains})

	cs, err := chunks(mod)
	if err != nil {
		t.Fatalf("a table with %d entries was rejected: %v", maxChunks, err)
	}
	if len(cs) != maxChunks {
		t.Fatalf("read %d chunks, want %d", len(cs), maxChunks)
	}
	if !chunkSumsOK(mod, cs) {
		t.Error("chunk sums do not cover the sectors as built")
	}
	segLen := int(binary.LittleEndian.Uint32(mod[offSegTable+8:]))
	segSum := binary.LittleEndian.Uint32(mod[offSegTable+12:])
	if got := wordSum(mod[segOffset : segOffset+segLen]); got != segSum {
		t.Errorf("segment sum 0x%08x, header says 0x%08x", got, segSum)
	}
	if got := loaderSum(mod, cs); got != segSum {
		t.Errorf("loader sum 0x%08x, header says 0x%08x", got, segSum)
	}
}

func TestSecondCompressedSegmentIsUnpacked(t *testing.T) {
	seg0 := []([]byte){bytes.Repeat([]byte("a"), 0x900), bytes.Repeat([]byte("b"), 0x900)}
	seg1 := []([]byte){bytes.Repeat([]byte("c"), 0x900), bytes.Repeat([]byte("\x00image"), 0x900)}
	mod := packContainer(t, [][]([]byte){seg0, seg1})

	cs, err := chunks(mod)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := plainOf(mod, cs)
	if err != nil {
		t.Fatal(err)
	}
	more, end, err := nextSegments(mod, cs)
	if err != nil {
		t.Fatalf("nextSegments: %v", err)
	}
	if want := bytes.Join(seg1, nil); !bytes.Equal(more, want) {
		t.Errorf("segment 1 unpacked to %d bytes, want %d", len(more), len(want))
	}
	if end != len(mod) {
		t.Errorf("segments stop at 0x%x, container ends at 0x%x", end, len(mod))
	}
	if !bytes.Equal(plain, bytes.Join(seg0, nil)) {
		t.Error("segment 0 does not unpack as built")
	}
}

func TestRawTailIsLeftAlone(t *testing.T) {
	seg0 := []([]byte){bytes.Repeat([]byte("z"), 0x900)}
	tail := bytes.Repeat([]byte{0x5a}, 0x400)
	mod := append(packContainer(t, [][]([]byte){seg0}), tail...)

	cs, err := chunks(mod)
	if err != nil {
		t.Fatal(err)
	}
	more, end, err := nextSegments(mod, cs)
	if err != nil {
		t.Fatalf("nextSegments: %v", err)
	}
	if len(more) != 0 {
		t.Errorf("found a second segment where the tail is plain data: %d bytes", len(more))
	}
	if got := mod[end:end+len(tail)]; !bytes.Equal(got, tail) {
		t.Error("the raw tail must stay readable as it is")
	}
}

