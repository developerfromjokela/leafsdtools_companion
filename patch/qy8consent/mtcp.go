package qy8consent

import (
	"encoding/binary"
	"fmt"

	"LeafSDTools_Companion/patch/qy8consent/lz4hc"
)

const sectorSize = 512

const (
	offPayloadLen = 0x00 // container length, less this header
	offSum4       = 0x34 // word sum of everything after this header
	offName       = 0x16 // the map version, e.g. "G218ENNI.120"
	offSegTable   = 0x90 // per-segment entries, 0x10 bytes each
	segOffset     = 0x200
)

const (
	offChunkCnt  = 0x04
	offReserved  = 0x1c // three words the loader sums but nothing reads
	offChunkEnts = 0x20
	chunkEntSize = 0x20

	// maxChunks is how many chunk entries fit in a segment's metadata sector.
	maxChunks = (sectorSize - offChunkEnts) / chunkEntSize
)

type chunk struct {
	at       int
	sectors  int
	plain    int
	packed   int
	plainAt  int
	tableEnt int // offset of the entry inside the container, 0 when unknown
}

// wordSum is the container's checksum throughout: a plain 32-bit sum of
// little-endian words, not a CRC.
func wordSum(b []byte) uint32 {
	var s uint32
	for i := 0; i+4 <= len(b); i += 4 {
		s += binary.LittleEndian.Uint32(b[i:])
	}
	return s
}

func chunks(mod []byte) ([]chunk, error) { return chunksAt(mod, segOffset) }

// chunksAt reads the chunk table of the segment whose metadata sector starts
// at table.
func chunksAt(mod []byte, table int) ([]chunk, error) {
	if len(mod) < table+sectorSize {
		return nil, fmt.Errorf("container is too small for MTCP metadata")
	}
	if string(mod[table:table+4]) != "MTCP" {
		return nil, fmt.Errorf("segment at 0x%x is not an MTCP segment", table)
	}
	count := int(binary.LittleEndian.Uint32(mod[table+offChunkCnt:]))
	if count < 1 || count > maxChunks {
		return nil, fmt.Errorf("MTCP chunk count %d out of range", count)
	}
	out := make([]chunk, count)
	at, plainAt := int64(table+sectorSize), int64(0)
	for i := range out {
		e := mod[table+offChunkEnts+i*chunkEntSize:]
		sectors := int64(binary.LittleEndian.Uint32(e[0:]))
		plain := int64(binary.LittleEndian.Uint32(e[4:]))
		packed := int64(binary.LittleEndian.Uint32(e[8:]))
		room := sectors * sectorSize
		if sectors < 1 || room > int64(len(mod)) || packed < 1 || packed > room || at > int64(len(mod)) || room > int64(len(mod))-at {
			return nil, fmt.Errorf("MTCP chunk %d sizes exceed the container", i)
		}
		if plain < 1 || plain > maxUnpackedSize || plainAt > maxUnpackedSize-plain {
			return nil, fmt.Errorf("MTCP unpacked size exceeds the 512 MiB cap")
		}
		out[i] = chunk{
			at:       int(at),
			sectors:  int(sectors),
			plain:    int(plain),
			packed:   int(packed),
			plainAt:  int(plainAt),
			tableEnt: table + offChunkEnts + i*chunkEntSize,
		}
		plainAt += plain
		at += room
	}
	return out, nil
}

// chunkSumsOK reports whether every chunk's stored sum covers its sectors.
func chunkSumsOK(mod []byte, cs []chunk) bool {
	for _, c := range cs {
		if wordSum(mod[c.at:c.at+c.sectors*sectorSize]) != binary.LittleEndian.Uint32(mod[c.tableEnt+12:]) {
			return false
		}
	}
	return len(cs) > 0
}

// nextSegments decompresses every MTCP segment after segment 0 and reports
// where their data stops in the container. A single-segment container stops
// right after segment 0, so the rest of the ROM image is taken as it is stored.
func nextSegments(mod []byte, cs []chunk) ([]byte, int, error) {
	end := cs[len(cs)-1].at + cs[len(cs)-1].sectors*sectorSize
	var out []byte
	for end+sectorSize <= len(mod) {
		next, err := chunksAt(mod, end)
		if err != nil || !chunkSumsOK(mod, next) {
			break
		}
		p, err := plainOf(mod, next)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, p...)
		end = next[len(next)-1].at + next[len(next)-1].sectors*sectorSize
	}
	return out, end, nil
}

func plainOf(mod []byte, cs []chunk) ([]byte, error) {
	total := 0
	for _, c := range cs {
		total += c.plain
	}
	out := make([]byte, 0, total)
	for i, c := range cs {
		p, err := lz4hc.Uncompress(mod[c.at:c.at+c.packed], c.plain)
		if err != nil {
			return nil, fmt.Errorf("chunk %d: %w", i, err)
		}
		out = append(out, p...)
	}
	return out, nil
}

// loaderSum is the segment's metadata sector plus its chunk sectors: what the
// NK2 loader adds up and compares against the segment's stored sum. The
// segment table's own length field covers exactly this range.
func loaderSum(mod []byte, cs []chunk) uint32 {
	s := wordSum(mod[segOffset : segOffset+sectorSize])
	for _, c := range cs {
		s += wordSum(mod[c.at : c.at+c.sectors*sectorSize])
	}
	return s
}

func writeChunk(mod []byte, cs []chunk, i int, packed []byte) {
	c := cs[i]
	room := c.sectors * sectorSize
	copy(mod[c.at:c.at+room], packed)
	clear(mod[c.at+len(packed) : c.at+room])

	e := mod[c.tableEnt:]
	binary.LittleEndian.PutUint32(e[8:], uint32(len(packed)))
	binary.LittleEndian.PutUint32(e[12:], wordSum(mod[c.at:c.at+room]))
	cs[i].packed = len(packed)
}
