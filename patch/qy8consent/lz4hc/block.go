package lz4hc

import "errors"

// ErrCorrupt is returned when a block does not decode to the expected length.
var ErrCorrupt = errors.New("lz4hc: corrupt block")

func Uncompress(src []byte, uncompressedLen int) ([]byte, error) {
	dst := make([]byte, 0, uncompressedLen)
	for i := 0; i < len(src); {
		token := int(src[i])
		i++

		litLen := token >> mlBits
		if litLen == runMask {
			for {
				if i >= len(src) {
					return nil, ErrCorrupt
				}
				b := int(src[i])
				i++
				litLen += b
				if b != 255 {
					break
				}
			}
		}
		if i+litLen > len(src) {
			return nil, ErrCorrupt
		}
		dst = append(dst, src[i:i+litLen]...)
		i += litLen
		if i == len(src) {
			break
		}

		if i+2 > len(src) {
			return nil, ErrCorrupt
		}
		offset := int(read16(src, i))
		i += 2
		matchLen := token&mlMask + minMatch
		if token&mlMask == mlMask {
			for {
				if i >= len(src) {
					return nil, ErrCorrupt
				}
				b := int(src[i])
				i++
				matchLen += b
				if b != 255 {
					break
				}
			}
		}
		if offset == 0 || offset > len(dst) {
			return nil, ErrCorrupt
		}
		// Overlapping copies are legal and common, so copy byte by byte.
		for p := len(dst) - offset; matchLen > 0; matchLen-- {
			dst = append(dst, dst[p])
			p++
		}
	}
	if len(dst) != uncompressedLen {
		return nil, ErrCorrupt
	}
	return dst, nil
}
