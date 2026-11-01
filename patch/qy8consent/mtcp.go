package qy8consent

import (
	"encoding/binary"
	"fmt"
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

	// loaderSpan is how much of the header sector the loader checksums.
	loaderSpan = 0x1e0
)

type chunk struct {
	at      int
	sectors int
	plain   int
	packed  int
	plainAt int
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

func chunks(mod []byte) ([]chunk, error) {
	if len(mod) < segOffset+sectorSize {
		return nil, fmt.Errorf("container is too small for MTCP metadata")
	}
	if string(mod[segOffset:segOffset+4]) != "MTCP" {
		return nil, fmt.Errorf("segment 0 is not an MTCP segment")
	}
	count := int(binary.LittleEndian.Uint32(mod[segOffset+offChunkCnt:]))
	if count < 1 || segOffset+offChunkEnts+count*0x20 > segOffset+loaderSpan {
		return nil, fmt.Errorf("MTCP chunk count %d out of range", count)
	}
	out := make([]chunk, count)
	at, plainAt := int64(segOffset+sectorSize), int64(0)
	for i := range out {
		e := mod[segOffset+offChunkEnts+i*0x20:]
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
			at:      int(at),
			sectors: int(sectors),
			plain:   int(plain),
			packed:  int(packed),
			plainAt: int(plainAt),
		}
		plainAt += plain
		at += room
	}
	return out, nil
}

// loaderSum is loaderSpan bytes of the header sector plus the chunk
// sectors: what the NK2 loader checks against.
func loaderSum(mod []byte, cs []chunk) uint32 {
	s := wordSum(mod[segOffset : segOffset+loaderSpan])
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

	e := mod[segOffset+offChunkEnts+i*0x20:]
	binary.LittleEndian.PutUint32(e[8:], uint32(len(packed)))
	binary.LittleEndian.PutUint32(e[12:], wordSum(mod[c.at:c.at+room]))
	cs[i].packed = len(packed)
}
