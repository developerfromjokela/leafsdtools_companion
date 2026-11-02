package wince

import (
	"errors"
	"sort"
)

const (
	cmpChunkSize  = 4096
	cmpWindowBits = 16
	cmpE8FileSize = 12000000
	// window=16 -> positionSlots[1] = 32 slots -> 256 + 32*8 main symbols.
	cmpMainElems = numChars + (32 << 3)
	// minMatch + 7 (primary) + 248 (highest length-tree symbol)
	cmpMaxMatch = minMatch + numPrimaryLengths + secondaryNumElements - 1
)

var ErrCompressTooLarge = errors.New("wince: data too large for the 24-bit ROM compression header")

// lzxCompress compresses data into the WinCE ROM compressed-file format.
// data must not be empty.
func lzxCompress(data []byte) ([]byte, error) {
	n := len(data)
	if n == 0 {
		return nil, errors.New("wince: cannot compress empty data")
	}
	chunks := (n + cmpChunkSize - 1) / cmpChunkSize
	hdr := (chunks + 1) * 3
	out := make([]byte, hdr, hdr+n/2+64)
	put24(out, 0, n)

	for c := 0; c < chunks; c++ {
		lo := c * cmpChunkSize
		hi := min(lo+cmpChunkSize, n)
		payload := lzxEncodeChunk(data[lo:hi])

		var ch [16]byte
		le.PutUint32(ch[0:], cmpWindowBits)
		le.PutUint32(ch[4:], uint32(hi-lo))
		le.PutUint32(ch[8:], uint32(hi-lo))
		le.PutUint32(ch[12:], uint32(len(payload)))
		out = append(out, ch[:]...)
		out = append(out, payload...)

		if len(out) >= 1<<24 {
			return nil, ErrCompressTooLarge
		}
		put24(out, 3*(c+1), len(out))
	}
	if n >= 1<<24 {
		return nil, ErrCompressTooLarge
	}
	return out, nil
}

func put24(b []byte, off, v int) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v >> 16)
}

type bitWriter struct {
	out []byte
	acc uint32
	n   int // pending bits in acc (< 16)
}

func (w *bitWriter) write(v uint32, bits int) {
	for bits > 0 {
		take := 16 - w.n
		if take > bits {
			take = bits
		}
		part := (v >> uint(bits-take)) & (1<<uint(take) - 1)
		w.acc = w.acc<<uint(take) | part
		w.n += take
		bits -= take
		if w.n == 16 {
			w.out = append(w.out, byte(w.acc), byte(w.acc>>8))
			w.acc, w.n = 0, 0
		}
	}
}

func (w *bitWriter) flush() {
	if w.n > 0 {
		w.acc <<= uint(16 - w.n)
		w.out = append(w.out, byte(w.acc), byte(w.acc>>8))
		w.acc, w.n = 0, 0
	}
}

func huffmanLengths(freq []int, maxLen int) []int {
	lens := make([]int, len(freq))
	f := append([]int(nil), freq...)
	var syms []int
	for i, v := range f {
		if v > 0 {
			syms = append(syms, i)
		}
	}
	if len(syms) == 0 {
		return lens
	} else if len(syms) == 1 {
		lens[syms[0]] = 1
		other := 0
		if syms[0] == 0 {
			other = 1
		}
		lens[other] = 1
		return lens
	}
	for {
		huffBuild(f, syms, lens)
		longest := 0
		for _, l := range lens {
			if l > longest {
				longest = l
			}
		}
		if longest <= maxLen {
			return lens
		}
		for _, s := range syms { // flatten the distribution and retry
			f[s] = (f[s] + 1) / 2
		}
	}
}

func huffBuild(f, syms, lens []int) {
	for i := range lens {
		lens[i] = 0
	}
	order := append([]int(nil), syms...)
	sort.SliceStable(order, func(a, b int) bool { return f[order[a]] < f[order[b]] })
	m := len(order)

	w := make([]int, 0, 2*m)
	for _, s := range order {
		w = append(w, f[s])
	}
	parent := make([]int, 2*m)

	li, ii := 0, m
	for k := 0; k < m-1; k++ {
		var pick [2]int
		for t := 0; t < 2; t++ {
			if li < m && (ii >= len(w) || w[li] <= w[ii]) {
				pick[t] = li
				li++
			} else {
				pick[t] = ii
				ii++
			}
		}
		w = append(w, w[pick[0]]+w[pick[1]])
		parent[pick[0]] = len(w) - 1
		parent[pick[1]] = len(w) - 1
	}

	depth := make([]int, len(w))
	for idx := len(w) - 2; idx >= 0; idx-- {
		depth[idx] = depth[parent[idx]] + 1
	}
	for i, s := range order {
		lens[s] = depth[i]
	}
}

func canonCodes(lens []int) []uint32 {
	var count [18]int
	for _, l := range lens {
		if l > 0 {
			count[l]++
		}
	}
	var next [18]uint32
	code := uint32(0)
	for l := 1; l <= 16; l++ {
		code = (code + uint32(count[l-1])) << 1
		next[l] = code
	}
	codes := make([]uint32, len(lens))
	for s, l := range lens {
		if l > 0 {
			codes[s] = next[l]
			next[l]++
		}
	}
	return codes
}

// symbol = (17 - len) % 17.
func writeTree(w *bitWriter, lens []int) {
	type item struct{ sym, extra, ebits int }
	var seq []item

	n := len(lens)
	for i := 0; i < n; {
		if lens[i] != 0 {
			seq = append(seq, item{(17 - lens[i]) % 17, 0, 0})
			i++
			continue
		}
		run := 0
		for i+run < n && lens[i+run] == 0 {
			run++
		}
		i += run
		for run > 0 {
			switch {
			case run >= 20:
				c := min(run, 51)
				seq = append(seq, item{18, c - 20, 5})
				run -= c
			case run >= 4:
				seq = append(seq, item{17, run - 4, 4})
				run = 0
			default:
				seq = append(seq, item{0, 0, 0})
				run--
			}
		}
	}

	var freq [pretreeNumElements]int
	for _, it := range seq {
		freq[it.sym]++
	}
	pl := huffmanLengths(freq[:], 15) // 4 bits per length
	pc := canonCodes(pl)
	for x := 0; x < pretreeNumElements; x++ {
		w.write(uint32(pl[x]), 4)
	}
	for _, it := range seq {
		w.write(pc[it.sym], pl[it.sym])
		if it.ebits > 0 {
			w.write(uint32(it.extra), it.ebits)
		}
	}
}

type lzToken struct {
	lit    byte
	length int // 0 => literal
	offset int
}

func lzParse(d []byte) []lzToken {
	n := len(d)
	const hashBits = 12
	head := make([]int32, 1<<hashBits)
	for i := range head {
		head[i] = -1
	}
	prev := make([]int32, n)
	hash := func(p int) uint32 {
		v := uint32(d[p])<<16 | uint32(d[p+1])<<8 | uint32(d[p+2])
		return (v * 2654435761) >> (32 - hashBits)
	}
	insert := func(p int) {
		if p+3 <= n {
			h := hash(p)
			prev[p] = head[h]
			head[h] = int32(p)
		}
	}

	var toks []lzToken
	for i := 0; i < n; {
		bestLen, bestOff := 0, 0
		if i+3 <= n {
			cand := head[hash(i)]
			maxl := min(cmpMaxMatch, n-i)
			for tries := 0; cand >= 0 && tries < 64; tries++ {
				c := int(cand)
				l := 0
				for l < maxl && d[c+l] == d[i+l] {
					l++
				}
				if l > bestLen {
					bestLen, bestOff = l, i-c
				}
				cand = prev[c]
			}
		}
		if bestLen >= 3 && (bestLen >= 4 || bestOff <= 512) {
			toks = append(toks, lzToken{length: bestLen, offset: bestOff})
			for p := i; p < i+bestLen; p++ {
				insert(p)
			}
			i += bestLen
		} else {
			toks = append(toks, lzToken{lit: d[i]})
			insert(i)
			i++
		}
	}
	return toks
}

func lzxE8Encode(d []byte) {
	n := len(d)
	if n < 10 {
		return
	}
	const fs = int64(cmpE8FileSize)
	for i := 0; i < n-10; i++ {
		if d[i] != 0xE8 {
			continue
		}
		rel := int64(int32(le.Uint32(d[i+1:])))
		pos := int64(i)
		if rel >= -pos && rel < fs {
			var abs int64
			if rel < fs-pos {
				abs = rel + pos
			} else {
				abs = rel - fs
			}
			le.PutUint32(d[i+1:], uint32(int32(abs)))
		}
		i += 4
	}
}

// lzxEncodeChunk encodes up to 4096 bytes as one verbatim LZX block.
func lzxEncodeChunk(chunk []byte) []byte {
	data := append([]byte(nil), chunk...)
	lzxE8Encode(data)
	toks := lzParse(data)

	type enc struct{ main, lenSym, extra, extraBits int }
	encs := make([]enc, len(toks))
	mainFreq := make([]int, cmpMainElems)
	lenFreq := make([]int, secondaryNumElements)

	for i, t := range toks {
		if t.length == 0 {
			encs[i] = enc{main: int(t.lit), lenSym: -1}
			mainFreq[t.lit]++
			continue
		}
		formatted := t.offset + 2 // decoder subtracts 2
		slot := 0
		for slot+1 < len(positionBase) && positionBase[slot+1] <= formatted {
			slot++
		}
		l := t.length - minMatch
		hdr, lsym := l, -1
		if l >= numPrimaryLengths {
			hdr, lsym = numPrimaryLengths, l-numPrimaryLengths
			lenFreq[lsym]++
		}
		m := numChars + (slot << 3) + hdr
		mainFreq[m]++
		encs[i] = enc{main: m, lenSym: lsym, extra: formatted - positionBase[slot], extraBits: extraBits[slot]}
	}
	// The decoder only undoes the E8 translation when the main tree has a code
	// for 0xE8, so always give it one.
	if mainFreq[0xE8] == 0 {
		mainFreq[0xE8] = 1
	}

	mainLens := huffmanLengths(mainFreq, 16)
	lenLens := huffmanLengths(lenFreq, 16)
	mainCodes := canonCodes(mainLens)
	lenCodes := canonCodes(lenLens)

	w := &bitWriter{}
	// Translation header: bit 1 + 32-bit E8 file size.
	w.write(1, 1)
	w.write(uint32(cmpE8FileSize>>16), 16)
	w.write(uint32(cmpE8FileSize&0xffff), 16)
	// Block header: verbatim, length in uncompressed bytes.
	w.write(uint32(blockVerbatim), 3)
	w.write(uint32(len(data)), 24)
	writeTree(w, mainLens[:256])
	writeTree(w, mainLens[256:])
	writeTree(w, lenLens)

	for _, e := range encs {
		w.write(mainCodes[e.main], mainLens[e.main])
		if e.lenSym >= 0 {
			w.write(lenCodes[e.lenSym], lenLens[e.lenSym])
		}
		if e.extraBits > 0 {
			w.write(uint32(e.extra), e.extraBits)
		}
	}
	w.flush()
	return w.out
}
