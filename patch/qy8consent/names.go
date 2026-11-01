package qy8consent

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"LeafSDTools_Companion/patch/wince"
)

type moduleSection struct {
	va   uint32
	data []byte
}

func moduleSections(m *wince.Module) ([]moduleSection, error) {
	img, err := m.Image()
	if err != nil {
		return nil, fmt.Errorf("rebuild %s: %w", m.Name, err)
	}
	if len(img) < 0x40 {
		return nil, fmt.Errorf("rebuilt %s is truncated", m.Name)
	}
	pe := int(binary.LittleEndian.Uint32(img[0x3c:]))
	if pe < 0 || pe+24 > len(img) {
		return nil, fmt.Errorf("rebuilt %s has an invalid PE header", m.Name)
	}
	count := int(binary.LittleEndian.Uint16(img[pe+6:]))
	optSize := int(binary.LittleEndian.Uint16(img[pe+20:]))
	table := pe + 24 + optSize
	if count != len(m.O32s) || table < 0 || table+count*40 > len(img) {
		return nil, fmt.Errorf("rebuilt %s has an invalid section table", m.Name)
	}
	sections := make([]moduleSection, count)
	for i, o := range m.O32s {
		h := img[table+i*40:]
		size := int(binary.LittleEndian.Uint32(h[16:]))
		off := int(binary.LittleEndian.Uint32(h[20:]))
		if off < 0 || size < 0 || off > len(img) || size > len(img)-off {
			return nil, fmt.Errorf("rebuilt %s section %d is out of bounds", m.Name, i)
		}
		sections[i] = moduleSection{va: m.E32.VBase + o.RVA, data: img[off : off+size]}
	}
	return sections, nil
}

func nameRank(sections []moduleSection, name string) (uint32, error) {
	needle := append([]byte(name), 0)
	var ranks []uint32
	for _, s := range sections {
		for from := 0; from < len(s.data); {
			i := bytes.Index(s.data[from:], needle)
			if i < 0 {
				break
			}
			i += from
			if i == 0 || s.data[i-1] == 0 {
				ptr := s.va + uint32(i)
				for _, slots := range sections {
					for off := 0; off+4 <= len(slots.data); off += 4 {
						if binary.LittleEndian.Uint32(slots.data[off:]) == ptr {
							rank, ok := sortedRank(sections, slots, off)
							if ok {
								ranks = append(ranks, rank)
							}
						}
					}
				}
			}
			from = i + 1
		}
	}
	if len(ranks) == 0 {
		return 0, fmt.Errorf("%s has no ranked name pointers", name)
	}
	for _, rank := range ranks[1:] {
		if rank != ranks[0] {
			return 0, fmt.Errorf("%s ranks differ: %v", name, ranks)
		}
	}
	return ranks[0], nil
}

func sortedRank(sections []moduleSection, slots moduleSection, off int) (uint32, bool) {
	cur, ok := stringAt(sections, binary.LittleEndian.Uint32(slots.data[off:]))
	if !ok {
		return 0, false
	}
	rank := uint32(1)
	for off -= 4; off >= 0; off -= 4 {
		prev, ok := stringAt(sections, binary.LittleEndian.Uint32(slots.data[off:]))
		if !ok || prev >= cur {
			break
		}
		cur = prev
		rank++
	}
	return rank, true
}

func stringAt(sections []moduleSection, ptr uint32) (string, bool) {
	for _, s := range sections {
		if ptr < s.va || ptr >= s.va+uint32(len(s.data)) {
			continue
		}
		off := int(ptr - s.va)
		if off > 0 && s.data[off-1] != 0 {
			return "", false
		}
		for end := off; end < len(s.data) && end < off+128; end++ {
			c := s.data[end]
			if c == 0 {
				return string(s.data[off:end]), end > off
			}
			if c < 0x20 || c > 0x7e {
				return "", false
			}
		}
		return "", false
	}
	return "", false
}

func literalString(sections []moduleSection, code []byte, codeVA uint32, at int) (uint32, string, bool) {
	w := binary.LittleEndian.Uint32(code[at:])
	if w&0xfffff000 != 0xe59f2000 {
		return 0, "", false
	}
	lit := codeVA + uint32(at) + 8 + w&0xfff
	for _, s := range sections {
		if lit < s.va || lit+4 > s.va+uint32(len(s.data)) {
			continue
		}
		text, ok := stringAt(sections, binary.LittleEndian.Uint32(s.data[lit-s.va:]))
		return lit, text, ok
	}
	return 0, "", false
}
