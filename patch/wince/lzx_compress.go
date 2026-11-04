// lzx_compress is a Go port of the compression half of Microsoft's Windows CE "compress_lzx.dll" (CECompress).
package wince

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

var (
	// ErrBadStep is returned when step is not 1 or 2.
	ErrBadStep = errors.New("wince lzx: step must be 1 or 2")
	// ErrShortSource is returned when src is too short for the requested count/step combination.
	ErrShortSource = errors.New("wince lzx: source buffer too short")
)

const (
	windowBits  = 16
	numPosSlots = 32 // for a 2^16 window
	mainElems   = 256 + 8*numPosSlots
	lenElems    = 249
	alignElems  = 8
	preElems    = 20

	maxMatch = 257

	e8FileSize = 12000000

	cBlockVerbatim = 1
	cBlockAligned  = 2
	cBlockStored   = 3

	maxSize = 0xFFFFFF

	// Parse
	hashBits  = 13
	maxChain  = 32
	maxChain2 = 16 // chain depth for the 2-byte (length-2 match) finder
	niceLen   = 32
	inf       = ^uint32(0)

	unusedCost = 12 // assumed bit cost of a symbol the previous pass never used
)

// CECompress compresses all src using the default step of 1.
// pageSize 4096 selects 4 KiB blocks; any other value selects 1 KiB blocks.
func CECompress(src []byte, pageSize int) ([]byte, error) {
	return CECompressStep(src, len(src), 1, pageSize)
}

func CECompressStep(src []byte, count, step, pageSize int) ([]byte, error) {
	if count < 0 || count > maxSize {
		return nil, ErrTooLarge
	}
	if step != 1 && step != 2 {
		return nil, ErrBadStep
	}
	bits := uint(10)
	if pageSize == 4096 {
		bits = 12
	}
	bs := 1 << bits
	nblocks := 1
	if count > 0 {
		nblocks = (count-1)>>bits + 1
	}

	tableLen := 3 * (nblocks + 1)
	out := make([]byte, tableLen, tableLen+count/2+64)
	put24(out[0:], count)

	var enc encoder
	remaining := count
	for k := 0; k < nblocks; k++ {
		n := remaining
		if n > bs {
			n = bs
		}
		start := k * step * bs
		if start+n > len(src) {
			return nil, ErrShortSource
		}
		out = putUint32(out, windowBits)
		out = putUint32(out, uint32(n))
		if n > 0 {
			payload := enc.encodeFrame(src[start : start+n])
			out = putUint32(out, uint32(len(payload)))
			out = putUint32(out, uint32(n))
			out = append(out, payload...)
		}
		if len(out) > maxSize {
			return nil, fmt.Errorf("%w (output)", ErrTooLarge)
		}
		put24(out[3+3*k:], len(out))
		remaining -= n
	}
	return out, nil
}

func put24(b []byte, v int) {
	b[0], b[1], b[2] = byte(v), byte(v>>8), byte(v>>16)
}

func putUint32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// encodeFrame encodes one block (<= 32 KiB) as a single LZX frame
func (e *encoder) encodeFrame(data []byte) []byte {
	t := append([]byte(nil), data...)
	translateE8(t)

	best := encodeStored(t)

	var bestItems []item
	var verb []byte
	m := defaultModel()
	for pass := 0; pass < 3; pass++ {
		items := e.parse(t, m)
		p := encodeCompressed(items, len(t), false)
		if verb == nil || len(p) < len(verb) {
			verb = p
			bestItems = append(bestItems[:0], items...)
		}
		m = modelFromItems(items)
	}
	if len(verb) < len(best) {
		best = verb
	}
	if al := encodeCompressed(bestItems, len(t), true); len(al) < len(best) {
		best = al
	}
	return best
}

// bitWriter produces an LZX bitstream
type bitWriter struct {
	buf []byte
	acc uint32 // pending bits (low n bits valid)
	n   uint   // number of pending bits, always < 16 between calls
}

// write appends the low nbits bits of v (nbits <= 16), MSB first.
func (w *bitWriter) write(v uint32, nbits uint) {
	if nbits == 0 {
		return
	}
	w.acc = w.acc<<nbits | (v & (1<<nbits - 1))
	w.n += nbits
	if w.n >= 16 {
		w.n -= 16
		word := uint16(w.acc >> w.n)
		w.buf = append(w.buf, byte(word), byte(word>>8))
		w.acc &= 1<<w.n - 1
	}
}

// padToWord pads with zero bits up to the next 16-bit boundary (0-15 bits).
func (w *bitWriter) padToWord() {
	if w.n != 0 {
		w.write(0, 16-w.n)
	}
}

// padRaw aligns for an uncompressed block
func (w *bitWriter) padRaw() {
	if w.n == 0 {
		w.write(0, 16)
	} else {
		w.padToWord()
	}
}

func (w *bitWriter) putUint32LE(v uint32) {
	w.buf = append(w.buf, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// buildLengths computes length-limited Huffman code lengths for freq and
// stores them in lens (same length as freq). The resulting code is always
// complete (Kraft sum == 1) when at least one symbol is used: a lone symbol
// is paired with a dummy so that decoders never see an incomplete tree.
// An all-zero freq yields an all-zero (empty) tree.
func buildLengths(freq []uint32, maxLen int, lens []uint8) {
	n := len(freq)
	var used [mainElems]uint16
	nu := 0
	for i := 0; i < n; i++ {
		lens[i] = 0
		if freq[i] > 0 {
			used[nu] = uint16(i)
			nu++
		}
	}
	switch nu {
	case 0:
		return
	case 1:
		lens[used[0]] = 1
		d := 0
		if used[0] == 0 {
			d = 1
		}
		lens[d] = 1
		return
	}

	var w [mainElems]uint64
	for _, s := range used[:nu] {
		w[s] = uint64(freq[s])
	}
	syms := used[:nu]
	for {
		sorted := make([]uint16, nu)
		copy(sorted, syms)
		sort.Slice(sorted, func(a, b int) bool {
			if w[sorted[a]] != w[sorted[b]] {
				return w[sorted[a]] < w[sorted[b]]
			}
			return sorted[a] < sorted[b]
		})
		// Two-queue Huffman construction.
		var weight [2 * mainElems]uint64
		var parent [2 * mainElems]int16
		for i, s := range sorted {
			weight[i] = w[s]
		}
		qi, qj, qk := 0, nu, nu
		for k := 0; k < nu-1; k++ {
			var pick [2]int
			for t := 0; t < 2; t++ {
				if qi < nu && (qj >= qk || weight[qi] <= weight[qj]) {
					pick[t] = qi
					qi++
				} else {
					pick[t] = qj
					qj++
				}
			}
			weight[qk] = weight[pick[0]] + weight[pick[1]]
			parent[pick[0]] = int16(qk)
			parent[pick[1]] = int16(qk)
			qk++
		}
		root := qk - 1
		var depth [2 * mainElems]int
		depth[root] = 0
		for i := root - 1; i >= 0; i-- {
			depth[i] = depth[parent[i]] + 1
		}
		maxd := 0
		for i := 0; i < nu; i++ {
			if depth[i] > maxd {
				maxd = depth[i]
			}
		}
		if maxd <= maxLen {
			for i, s := range sorted {
				lens[s] = uint8(depth[i])
			}
			return
		}
		for _, s := range syms {
			w[s] = 1 + w[s]/2
		}
	}
}

// assignCodes computes canonical MSB-first codes (shorter codes first, ties
// broken by symbol index) for the given lengths.
func assignCodes(lens []uint8, codes []uint16) {
	var count [18]uint32
	for _, l := range lens {
		count[l]++
	}
	count[0] = 0
	var next [18]uint32
	code := uint32(0)
	for b := 1; b <= 16; b++ {
		code = (code + count[b-1]) << 1
		next[b] = code
	}
	for i, l := range lens {
		if l != 0 {
			codes[i] = uint16(next[l])
			next[l]++
		}
	}
}

var (
	posBase  [numPosSlots]uint32
	posExtra [numPosSlots]uint8
	slotOf   [1 << 13]uint8 // formatted offset -> position slot
)

func init() {
	pos := uint32(0)
	for s := 0; s < numPosSlots; s++ {
		e := uint8(0)
		if s >= 4 {
			e = uint8((s - 2) / 2)
			if e > 17 {
				e = 17
			}
		}
		posExtra[s] = e
		posBase[s] = pos
		pos += 1 << e
	}
	s := 0
	for f := range slotOf {
		for s+1 < numPosSlots && uint32(f) >= posBase[s+1] {
			s++
		}
		slotOf[f] = uint8(s)
	}
}

// translateE8 performs the forward x86 CALL translation on one frame,
// converting relative CALL operands to absolute ones (the inverse of what the
// decoder does)
func translateE8(d []byte) {
	n := len(d)
	if n <= 10 {
		return
	}
	end := n - 10
	for i := 0; i < end; {
		if d[i] != 0xE8 {
			i++
			continue
		}
		v := int32(binary.LittleEndian.Uint32(d[i+1:]))
		cur := int32(i)
		if v >= -cur && v < e8FileSize {
			var a int32
			if v < e8FileSize-cur {
				a = v + cur
			} else {
				a = v - e8FileSize
			}
			binary.LittleEndian.PutUint32(d[i+1:], uint32(a))
		}
		i += 5
	}
}

type item struct {
	mlen  uint16
	lit   byte
	slot  uint8
	ebits uint8
	extra uint32 // value of the position "extra" bits
}

type preTok struct {
	sym   uint8
	extra uint8
	nbits uint8
}

// rleLengths turns code lengths into pretree tokens
func rleLengths(cur, prev []uint8, toks []preTok) []preTok {
	n := len(cur)
	delta := func(i int, l uint8) uint8 { return uint8((int(prev[i]) - int(l) + 17) % 17) }
	for i := 0; i < n; {
		l := cur[i]
		r := 1
		for i+r < n && cur[i+r] == l {
			r++
		}
		if l == 0 {
			switch {
			case r >= 20:
				c := r
				if c > 20+31 {
					c = 20 + 31
				}
				toks = append(toks, preTok{18, uint8(c - 20), 5})
				i += c
			case r >= 4:
				toks = append(toks, preTok{17, uint8(r - 4), 4})
				i += r
			default:
				toks = append(toks, preTok{delta(i, 0), 0, 0})
				i++
			}
			continue
		}
		if r >= 4 {
			c := 5
			if r >= 8 && r-5 < 4 {
				c = 4
			}
			if c > r {
				c = r
			}
			toks = append(toks, preTok{19, uint8(c - 4), 1}, preTok{delta(i, l), 0, 0})
			i += c
			continue
		}
		toks = append(toks, preTok{delta(i, l), 0, 0})
		i++
	}
	return toks
}

// writeTree emits the pretree plus the pretree-coded lengths for lens lo&hi.
func writeTree(w *bitWriter, lens []uint8, lo, hi int) {
	var zero [mainElems]uint8
	var toksBuf [mainElems]preTok
	toks := rleLengths(lens[lo:hi], zero[lo:hi], toksBuf[:0])

	var freq [preElems]uint32
	for _, t := range toks {
		freq[t.sym]++
	}
	var plens [preElems]uint8
	var pcodes [preElems]uint16
	buildLengths(freq[:], 15, plens[:])
	assignCodes(plens[:], pcodes[:])
	for i := 0; i < preElems; i++ {
		w.write(uint32(plens[i]), 4)
	}
	for _, t := range toks {
		w.write(uint32(pcodes[t.sym]), uint(plens[t.sym]))
		w.write(uint32(t.extra), uint(t.nbits))
	}
}

func writeStreamHeader(w *bitWriter) {
	w.write(1, 1) // E8 translation enabled
	w.write(e8FileSize>>16, 16)
	w.write(e8FileSize&0xffff, 16)
}

func writeBlockHeader(w *bitWriter, typ int, size int) {
	w.write(uint32(typ), 3)
	w.write(uint32(size>>8), 16)
	w.write(uint32(size&0xff), 8)
}

func encodeStored(data []byte) []byte {
	var w bitWriter
	w.buf = make([]byte, 0, len(data)+32)
	writeStreamHeader(&w)
	writeBlockHeader(&w, cBlockStored, len(data))
	w.padRaw()
	w.putUint32LE(1)
	w.putUint32LE(1)
	w.putUint32LE(1)
	w.buf = append(w.buf, data...)
	if len(data)&1 != 0 {
		w.buf = append(w.buf, 0)
	}
	return w.buf
}

// encodeCompressed builds a verbatim non-aligned or aligned-offset frame payload for the given parse.
// dataLen is the frame's uncompressed size.
func encodeCompressed(items []item, dataLen int, aligned bool) []byte {
	var mainFreq [mainElems]uint32
	var lenFreq [lenElems]uint32
	var alignFreq [alignElems]uint32
	for i := range items {
		it := &items[i]
		if it.mlen == 0 {
			mainFreq[it.lit]++
			continue
		}
		ml := int(it.mlen) - minMatch
		first := ml
		if ml >= 7 {
			first = 7
			lenFreq[ml-7]++
		}
		mainFreq[256+int(it.slot)*8+first]++
		if aligned && it.ebits >= 3 {
			alignFreq[it.extra&7]++
		}
	}
	var mainLens [mainElems]uint8
	var lenLens [lenElems]uint8
	var alignLens [alignElems]uint8
	var mainCodes [mainElems]uint16
	var lenCodes [lenElems]uint16
	var alignCodes [alignElems]uint16
	buildLengths(mainFreq[:], 16, mainLens[:])
	buildLengths(lenFreq[:], 16, lenLens[:])
	assignCodes(mainLens[:], mainCodes[:])
	assignCodes(lenLens[:], lenCodes[:])
	if aligned {
		buildLengths(alignFreq[:], 7, alignLens[:])
		assignCodes(alignLens[:], alignCodes[:])
	}

	var w bitWriter
	w.buf = make([]byte, 0, dataLen+64)
	writeStreamHeader(&w)
	typ := cBlockVerbatim
	if aligned {
		typ = cBlockAligned
	}
	writeBlockHeader(&w, typ, dataLen)
	if aligned {
		for _, l := range alignLens {
			w.write(uint32(l), 3)
		}
	}
	writeTree(&w, mainLens[:], 0, 256)
	writeTree(&w, mainLens[:], 256, mainElems)
	writeTree(&w, lenLens[:], 0, lenElems)

	for i := range items {
		it := &items[i]
		if it.mlen == 0 {
			w.write(uint32(mainCodes[it.lit]), uint(mainLens[it.lit]))
			continue
		}
		ml := int(it.mlen) - minMatch
		first := ml
		if ml >= 7 {
			first = 7
		}
		sym := 256 + int(it.slot)*8 + first
		w.write(uint32(mainCodes[sym]), uint(mainLens[sym]))
		if ml >= 7 {
			w.write(uint32(lenCodes[ml-7]), uint(lenLens[ml-7]))
		}
		if it.ebits > 0 {
			if aligned && it.ebits >= 3 {
				if it.ebits > 3 {
					w.write(it.extra>>3, uint(it.ebits-3))
				}
				a := it.extra & 7
				w.write(uint32(alignCodes[a]), uint(alignLens[a]))
			} else {
				w.write(it.extra, uint(it.ebits))
			}
		}
	}
	w.padToWord()
	return w.buf
}

type model struct {
	main [mainElems]uint32
	len  [lenElems]uint32
}

func defaultModel() *model {
	m := &model{}
	for s := 0; s < 256; s++ {
		m.main[s] = 8
	}
	for s := 256; s < mainElems; s++ {
		if (s-256)>>3 < 3 {
			m.main[s] = 7
		} else {
			m.main[s] = 10
		}
	}
	for i := range m.len {
		m.len[i] = 6
	}
	return m
}

// modelFromItems derives a cost model from the code lengths a parse would produce
func modelFromItems(items []item) *model {
	var mf [mainElems]uint32
	var lf [lenElems]uint32
	for i := range items {
		it := &items[i]
		if it.mlen == 0 {
			mf[it.lit]++
			continue
		}
		ml := int(it.mlen) - minMatch
		first := ml
		if ml >= 7 {
			first = 7
			lf[ml-7]++
		}
		mf[256+int(it.slot)*8+first]++
	}
	var ml [mainElems]uint8
	var ll [lenElems]uint8
	buildLengths(mf[:], 16, ml[:])
	buildLengths(lf[:], 16, ll[:])
	m := &model{}
	for i, l := range ml {
		if mf[i] == 0 {
			m.main[i] = unusedCost
		} else {
			m.main[i] = uint32(l)
		}
	}
	for i, l := range ll {
		if lf[i] == 0 {
			m.len[i] = unusedCost
		} else {
			m.len[i] = uint32(l)
		}
	}
	return m
}

type node struct {
	cost  uint32
	from  int32
	mlen  uint16
	slot  uint8
	ebits uint8
	extra uint32
	reps  [3]uint32
}

type edge struct {
	slot  uint8
	ebits uint8
	extra uint32
	reps  [3]uint32
}

// makeEdge resolves an actual match offset against the repeat-offset state,
// yielding the position slot, extra bits and the updated state.
func makeEdge(reps [3]uint32, off uint32) edge {
	switch off {
	case reps[0]:
		return edge{slot: 0, reps: reps}
	case reps[1]:
		return edge{slot: 1, reps: [3]uint32{reps[1], reps[0], reps[2]}}
	case reps[2]:
		return edge{slot: 2, reps: [3]uint32{reps[2], reps[1], reps[0]}}
	}
	f := off + 2
	s := slotOf[f]
	return edge{
		slot:  s,
		ebits: posExtra[s],
		extra: f - posBase[s],
		reps:  [3]uint32{off, reps[0], reps[1]},
	}
}

func (m *model) matchCost(l int, e *edge) uint32 {
	base := 256 + int(e.slot)*8
	if l-minMatch < 7 {
		return m.main[base+l-minMatch] + uint32(e.ebits)
	}
	return m.main[base+7] + m.len[l-9] + uint32(e.ebits)
}

// encoder carries reusable scratch state for the parser.
type encoder struct {
	head   [1 << hashBits]int32
	chain  []int32
	head2  [1 << 16]int32
	chain2 []int32
	nodes  []node
	items  []item
}

func hash3(a, b, c byte) uint32 {
	return ((uint32(a) << 16) | (uint32(b) << 8) | uint32(c)) * 2654435761 >> (32 - hashBits)
}

func matchLen(d []byte, i, j, max int) int {
	n := 0
	for n < max && d[i+n] == d[j+n] {
		n++
	}
	return n
}

func setMatch(nd *node, cost uint32, from, l int, e *edge) {
	nd.cost = cost
	nd.from = int32(from)
	nd.mlen = uint16(l)
	nd.slot = e.slot
	nd.ebits = e.ebits
	nd.extra = e.extra
	nd.reps = e.reps
}

type cand struct {
	e      edge
	lo, hi int
}

// parse computes a (near)optimal parse of data under cost model m.
func (e *encoder) parse(data []byte, m *model) []item {
	n := len(data)
	if cap(e.nodes) < n+1 {
		e.nodes = make([]node, n+1)
		e.chain = make([]int32, n+1)
		e.chain2 = make([]int32, n+1)
	}
	nodes := e.nodes[:n+1]
	for i := range nodes {
		nodes[i].cost = inf
	}
	for i := range e.head {
		e.head[i] = 0
	}
	for i := range e.head2 {
		e.head2[i] = 0
	}
	nodes[0] = node{reps: [3]uint32{1, 1, 1}}

	insert := func(i int) {
		if i+2 <= n {
			w := uint32(data[i]) | uint32(data[i+1])<<8
			e.chain2[i] = e.head2[w]
			e.head2[w] = int32(i + 1)
		}
		if i+3 <= n {
			h := hash3(data[i], data[i+1], data[i+2])
			e.chain[i] = e.head[h]
			e.head[h] = int32(i + 1)
		}
	}
	var cands [4 + maxChain]cand
	for i := 0; i < n; {
		cur := nodes[i]
		reps := cur.reps
		// Literal edge.
		if cost := cur.cost + m.main[data[i]]; cost < nodes[i+1].cost {
			nodes[i+1] = node{cost: cost, from: int32(i), reps: reps}
		}

		maxl := n - i
		if maxl > maxMatch {
			maxl = maxMatch
		}
		nc := 0
		longest := 0
		if maxl >= minMatch {
			// Repeat-offset candidates.
			for r := 0; r < 3; r++ {
				off := int(reps[r])
				if off > i {
					continue
				}
				l := matchLen(data, i, i-off, maxl)
				if l >= minMatch {
					cands[nc] = cand{makeEdge(reps, uint32(off)), minMatch, l}
					nc++
					if l > longest {
						longest = l
					}
				}
			}
			// Cheapest length-2 match at any near offset
			{
				w := uint32(data[i]) | uint32(data[i+1])<<8
				bestC := inf
				bestOff := 0
				p := int(e.head2[w]) - 1
				for steps := 0; p >= 0 && steps < maxChain2; steps++ {
					off := i - p
					s := slotOf[off+2]
					if c := m.main[256+int(s)*8] + uint32(posExtra[s]); c < bestC {
						bestC, bestOff = c, off
					}
					p = int(e.chain2[p]) - 1
				}
				if bestC != inf {
					cands[nc] = cand{makeEdge(reps, uint32(bestOff)), minMatch, minMatch}
					nc++
					if longest < minMatch {
						longest = minMatch
					}
				}
			}
			// Hash-chain candidates, min length is 3.
			if i+3 <= n {
				h := hash3(data[i], data[i+1], data[i+2])
				p := int(e.head[h]) - 1
				prevBest := 2
				for steps := 0; p >= 0 && steps < maxChain; steps++ {
					if prevBest < maxl && data[p+prevBest] == data[i+prevBest] || prevBest >= maxl {
						l := matchLen(data, i, p, maxl)
						if l > prevBest {
							cands[nc] = cand{makeEdge(reps, uint32(i-p)), prevBest + 1, l}
							nc++
							prevBest = l
							if l > longest {
								longest = l
							}
							if l >= maxl {
								break
							}
						}
					}
					p = int(e.chain[p]) - 1
				}
			}
		}
		insert(i)

		if longest >= niceLen {
			// Take the cheapest edge of maximal length and skip ahead.
			bestC := inf
			var be edge
			for k := 0; k < nc; k++ {
				if cands[k].hi == longest {
					if c := m.matchCost(longest, &cands[k].e); c < bestC {
						bestC = c
						be = cands[k].e
					}
				}
			}
			if cost := cur.cost + bestC; cost < nodes[i+longest].cost {
				setMatch(&nodes[i+longest], cost, i, longest, &be)
			}
			for j := i + 1; j < i+longest; j++ {
				insert(j)
			}
			i += longest
			continue
		}
		for k := 0; k < nc; k++ {
			c := &cands[k]
			base := 256 + int(c.e.slot)*8
			eb := uint32(c.e.ebits)
			l := c.lo
			for ; l <= c.hi && l-minMatch < 7; l++ {
				if cost := cur.cost + m.main[base+l-minMatch] + eb; cost < nodes[i+l].cost {
					setMatch(&nodes[i+l], cost, i, l, &c.e)
				}
			}
			for ; l <= c.hi; l++ {
				if cost := cur.cost + m.main[base+7] + eb + m.len[l-9]; cost < nodes[i+l].cost {
					setMatch(&nodes[i+l], cost, i, l, &c.e)
				}
			}
		}
		i++
	}

	items := e.items[:0]
	for k := n; k > 0; {
		nd := &nodes[k]
		if nd.mlen == 0 {
			items = append(items, item{lit: data[k-1]})
			k--
		} else {
			items = append(items, item{mlen: nd.mlen, slot: nd.slot, ebits: nd.ebits, extra: nd.extra})
			k -= int(nd.mlen)
		}
	}
	for a, b := 0, len(items)-1; a < b; a, b = a+1, b-1 {
		items[a], items[b] = items[b], items[a]
	}
	e.items = items
	return items
}
