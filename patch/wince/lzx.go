package wince

import (
	"encoding/binary"
	"errors"
)

// WinCE Decompressor: Decompress compressed files from Windows CE ROMs.

var errUnsupportedWindowSize = errors.New("unsupported window size range")

// LZX constants

const (
	pretreeNumElements   = 20
	secondaryNumElements = 249
	alignedNumElements   = 8
	numPrimaryLengths    = 7

	numChars = 256
	minMatch = 2

	pretreeMaxSymbols    = pretreeNumElements
	pretreeTableBits     = 6
	pretreeMaxCodeword   = 16
	maintreeMaxSymbols   = numChars + (51 << 3)
	maintreeTableBits    = 11
	maintreeMaxCodeword  = 16
	lentreeMaxSymbols    = secondaryNumElements
	lentreeTableBits     = 10
	lentreeMaxCodeword   = 16
	aligntreeMaxSymbols  = alignedNumElements
	aligntreeTableBits   = 7
	aligntreeMaxCodeword = 8

	lentableSafety = 64
)

type blockType int

const (
	blockInvalid      blockType = 0
	blockVerbatim     blockType = 1
	blockAligned      blockType = 2
	blockUncompressed blockType = 3
)

var positionSlots = []int{30, 32, 34, 36, 38, 42, 50, 66, 98, 162, 290}

var extraBits = []int{
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
	9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16,
	17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
}

var positionBase = []int{
	0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512,
	768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768,
	49152, 65536, 98304, 131072, 196608, 262144, 393216, 524288, 655360,
	786432, 917504, 1048576, 1179648, 1310720, 1441792, 1572864, 1703936,
	1835008, 1966080, 2097152,
}

// In-memory reader

type memReader struct {
	data []byte
	pos  int
}

func (r *memReader) tell() int       { return r.pos }
func (r *memReader) seekCur(off int) { r.pos += off }

// readByte returns the next byte, or ok=false (without advancing) at EOF.
func (r *memReader) readByte() (byte, bool) {
	if r.pos < len(r.data) {
		b := r.data[r.pos]
		r.pos++
		return b, true
	}
	return 0, false
}

// readLE reads up to n bytes as a little-endian unsigned integer.
func (r *memReader) readLE(n int) int {
	v := 0
	for k := 0; k < n; k++ {
		if r.pos < len(r.data) {
			v |= int(r.data[r.pos]) << uint(8*k)
			r.pos++
		}
	}
	return v
}

func (r *memReader) skip(n int) {
	if r.pos+n > len(r.data) {
		n = len(r.data) - r.pos
		if n < 0 {
			n = 0
		}
	}
	r.pos += n
}

func (r *memReader) readInto(dst []byte) {
	if r.pos < len(r.data) {
		r.pos += copy(dst, r.data[r.pos:])
	}
}

const bufferNumBits = 32

type bitBuffer struct {
	buffer   uint32
	bitsLeft int
	stream   *memReader
}

func (b *bitBuffer) reset() {
	b.buffer = 0
	b.bitsLeft = 0
}

func (b *bitBuffer) ensureBits(bits int) {
	for b.bitsLeft < bits {
		lo, _ := b.stream.readByte()
		hi, _ := b.stream.readByte()
		b.buffer |= (uint32(hi)<<8 | uint32(lo)) << uint(bufferNumBits-16-b.bitsLeft)
		b.bitsLeft += 16
	}
}

func (b *bitBuffer) peekBits(bits int) int {
	return int(b.buffer >> uint(bufferNumBits-(bits&0x1f)))
}

func (b *bitBuffer) removeBits(bits int) {
	b.buffer <<= uint(bits)
	b.bitsLeft -= bits
}

func (b *bitBuffer) readBits(bits int) int {
	ret := 0
	if bits > 0 {
		b.ensureBits(bits)
		ret = b.peekBits(bits)
		b.removeBits(bits)
	}
	return ret
}

// LZX state

type lzxState struct {
	r0, r1, r2 int

	mainElements   int
	headerRead     bool
	blockType      blockType
	blockLength    int
	blockRemaining int
	intelFilesize  int
	intelStarted   bool

	pretreeTable   []int
	pretreeLen     []int
	maintreeTable  []int
	maintreeLen    []int
	lentreeTable   []int
	lentreeLen     []int
	aligntreeTable []int
	aligntreeLen   []int

	windowSize int
	window     []byte
	windowPosn int
}

func newLZXState(window int) (*lzxState, error) {
	if window < 15 || window > 21 {
		return nil, errUnsupportedWindowSize
	}
	s := &lzxState{
		r0: 1, r1: 1, r2: 1,
		mainElements: numChars + (positionSlots[window-15] << 3),
		blockType:    blockInvalid,
	}
	s.pretreeTable = make([]int, (1<<pretreeTableBits)+(pretreeMaxSymbols<<1))
	s.pretreeLen = make([]int, pretreeMaxSymbols+lentableSafety)
	s.maintreeTable = make([]int, (1<<maintreeTableBits)+(maintreeMaxSymbols<<1))
	s.maintreeLen = make([]int, maintreeMaxSymbols+lentableSafety)
	s.lentreeTable = make([]int, (1<<lentreeTableBits)+(lentreeMaxSymbols<<1))
	s.lentreeLen = make([]int, lentreeMaxSymbols+lentableSafety)
	s.aligntreeTable = make([]int, (1<<aligntreeTableBits)+(aligntreeMaxSymbols<<1))
	s.aligntreeLen = make([]int, aligntreeMaxSymbols+lentableSafety)

	s.windowSize = 1 << uint(window&0x1f)
	s.window = make([]byte, s.windowSize)
	for i := range s.window {
		s.window[i] = 0xDC
	}
	return s, nil
}

type lzxDecoder struct {
	state *lzxState
}

func newLZXDecoder(window int) (*lzxDecoder, error) {
	st, err := newLZXState(window)
	if err != nil {
		return nil, err
	}
	return &lzxDecoder{state: st}, nil
}

// decompress decodes one chunk. It returns the decompressed bytes and a status
// (0 on success, -1 on failure). Any out-of-range access caused by corrupt
// input (which would raise in the Python original) is converted to -1.
func (d *lzxDecoder) decompress(in *memReader, inLen, outLen int) (out []byte, status int) {
	defer func() {
		if r := recover(); r != nil {
			out, status = nil, -1
		}
	}()

	st := d.state
	bb := &bitBuffer{stream: in}
	startPos := in.tell()
	endPos := startPos + inLen
	togo := outLen

	// Header: a zero bit (no encoder preprocessing), or a one bit followed by the
	// file translation size used for E8 preprocessing.
	if !st.headerRead {
		if bb.readBits(1) == 1 {
			i := bb.readBits(16)
			j := bb.readBits(16)
			st.intelFilesize = (i << 16) | j
		}
		st.headerRead = true
	}

	for togo > 0 {
		if st.blockRemaining == 0 {
			if st.blockType == blockUncompressed {
				if st.blockLength&1 == 1 {
					in.seekCur(1)
				}
				st.blockType = blockInvalid
				bb.reset()
			}

			st.blockType = blockType(bb.readBits(3))
			st.blockLength = bb.readBits(24)
			st.blockRemaining = st.blockLength

			if st.blockType == blockAligned {
				for i := 0; i < 8; i++ {
					st.aligntreeLen[i] = bb.readBits(3)
				}
				makeDecodeTable(aligntreeMaxSymbols, aligntreeTableBits, st.aligntreeLen, st.aligntreeTable)
			}

			if st.blockType == blockVerbatim || st.blockType == blockAligned {
				d.readLengths(st.maintreeLen, 0, 256, bb)
				d.readLengths(st.maintreeLen, 256, st.mainElements, bb)
				makeDecodeTable(maintreeMaxSymbols, maintreeTableBits, st.maintreeLen, st.maintreeTable)
				if st.maintreeLen[0xE8] != 0 {
					st.intelStarted = true
				}

				d.readLengths(st.lentreeLen, 0, secondaryNumElements, bb)
				makeDecodeTable(lentreeMaxSymbols, lentreeTableBits, st.lentreeLen, st.lentreeTable)
			} else if st.blockType == blockUncompressed {
				if endPos <= in.tell()+4 {
					return nil, -1
				}

				st.intelStarted = true
				bb.ensureBits(16)
				if bb.bitsLeft > 16 {
					in.seekCur(-2)
				}

				st.r0 = in.readLE(4)
				st.r1 = in.readLE(4)
				st.r2 = in.readLE(4)
			} else {
				return nil, -1
			}
		}

		if in.tell() > startPos+inLen {
			if in.tell() > startPos+inLen+2 || bb.bitsLeft < 16 {
				return nil, -1
			}
		}

		// NOTE: preserved verbatim from the Python original, which does
		//   togo -= block_remaining if block_remaining > togo else togo
		// i.e. togo becomes 0 unless the block is larger than what is left,
		// in which case togo goes negative and the final check below fails.
		if st.blockRemaining > togo {
			togo -= st.blockRemaining
		} else {
			togo = 0
		}

		st.windowPosn &= st.windowSize - 1
		if st.windowPosn+st.blockRemaining > st.windowSize {
			return nil, -1
		}

		switch st.blockType {
		case blockVerbatim, blockAligned:
			d.decompressBlock(bb)
		case blockUncompressed:
			if in.tell() >= endPos {
				return nil, -1
			}
			d.decompressUncompressed(in)
		default:
			return nil, -1
		}
	}

	if togo != 0 {
		return nil, -1
	}

	startWindowPos := st.windowPosn
	if startWindowPos == 0 {
		startWindowPos = st.windowSize
	}
	startWindowPos -= outLen
	if startWindowPos < 0 || startWindowPos+outLen > len(st.window) {
		return nil, -1
	}
	out = make([]byte, outLen)
	copy(out, st.window[startWindowPos:startWindowPos+outLen])

	// Optional x86 CALL (E8) preprocessing must be undone after decompression.
	d.undoE8Preprocessing(out)

	return out, 0
}

// undoE8Preprocessing translates x86 CALL instruction operands from absolute
// back to relative offsets, in place.
func (d *lzxDecoder) undoE8Preprocessing(out []byte) {
	st := d.state
	outLen := len(out)
	if outLen < 10 || !st.intelStarted {
		return
	}
	// E8 preprocessing is not disabled after the 32768th chunk of a XIP
	// compressed file (unlike LZX in cabinet files).
	fileSize := int64(st.intelFilesize)
	for i := 0; i < outLen-10; i++ {
		if out[i] == 0xE8 {
			abs := int64(int32(binary.LittleEndian.Uint32(out[i+1:])))
			pos := int64(i)
			// Values in [-2^31, pos) and [filesize, 2^31) are left unchanged.
			if -pos <= abs && abs < fileSize {
				if abs >= 0 {
					abs -= pos
				} else {
					abs += fileSize
				}
				binary.LittleEndian.PutUint32(out[i+1:], uint32(int32(abs)))
			}
			i += 4
		}
	}
}

// readLengths reads the pretree, then uses it to decode length values into lens[first:last].
func (d *lzxDecoder) readLengths(lens []int, first, last int, bb *bitBuffer) {
	st := d.state
	for x := 0; x < 20; x++ {
		st.pretreeLen[x] = bb.readBits(4)
	}
	makeDecodeTable(pretreeMaxSymbols, pretreeTableBits, st.pretreeLen, st.pretreeTable)

	x := first
	for x < last {
		z := d.readHuffSymPretree(bb)
		switch z {
		case 17:
			y := bb.readBits(4) + 4
			for k := 0; k < y; k++ {
				lens[x] = 0
				x++
			}
		case 18:
			y := bb.readBits(5) + 20
			for k := 0; k < y; k++ {
				lens[x] = 0
				x++
			}
		case 19:
			y := bb.readBits(1) + 4
			z = d.readHuffSymPretree(bb)
			z = (lens[x] + 17 - z) % 17
			for k := 0; k < y; k++ {
				lens[x] = z
				x++
			}
		default:
			z = (lens[x] + 17 - z) % 17
			lens[x] = z
			x++
		}
	}
}

func readHuffSym(table, lengths []int, nsyms, nbits int, bb *bitBuffer, codeword int) int {
	bb.ensureBits(codeword)
	i := table[bb.peekBits(nbits)]
	if i >= nsyms {
		j := uint32(1) << uint(bufferNumBits-nbits)
		for {
			j >>= 1
			i <<= 1
			if bb.buffer&j != 0 {
				i |= 1
			}
			if j == 0 {
				return 0
			}
			i = table[i]
			if i < nsyms {
				break
			}
		}
	}
	bb.removeBits(lengths[i])
	return i
}

func (d *lzxDecoder) readHuffSymPretree(bb *bitBuffer) int {
	return readHuffSym(d.state.pretreeTable, d.state.pretreeLen,
		pretreeMaxSymbols, pretreeTableBits, bb, pretreeMaxCodeword)
}

func (d *lzxDecoder) readHuffSymMaintree(bb *bitBuffer) int {
	return readHuffSym(d.state.maintreeTable, d.state.maintreeLen,
		maintreeMaxSymbols, maintreeTableBits, bb, maintreeMaxCodeword)
}

func (d *lzxDecoder) readHuffSymLentree(bb *bitBuffer) int {
	return readHuffSym(d.state.lentreeTable, d.state.lentreeLen,
		lentreeMaxSymbols, lentreeTableBits, bb, lentreeMaxCodeword)
}

func (d *lzxDecoder) readHuffSymAligntree(bb *bitBuffer) int {
	return readHuffSym(d.state.aligntreeTable, d.state.aligntreeLen,
		aligntreeMaxSymbols, aligntreeTableBits, bb, aligntreeMaxCodeword)
}

// makeDecodeTable builds a decoding table for a Huffman code.
func makeDecodeTable(nsyms, nbits int, length []int, table []int) bool {
	bitNum := 1
	pos := 0
	tableMask := 1 << uint(nbits)
	bitMask := tableMask >> 1
	nextSymbol := bitMask

	for bitNum <= nbits {
		for sym := 0; sym < nsyms; sym++ {
			if length[sym] == bitNum {
				leaf := pos
				pos += bitMask
				if pos > tableMask {
					return false
				}
				for k := 0; k < bitMask; k++ {
					table[leaf] = sym
					leaf++
				}
			}
		}
		bitMask >>= 1
		bitNum++
	}

	if pos != tableMask {
		for sym := pos; sym < tableMask; sym++ {
			table[sym] = 0
		}

		pos <<= 16
		tableMask <<= 16
		bitMask = 1 << 15

		for bitNum <= 16 {
			for sym := 0; sym < nsyms; sym++ {
				if length[sym] == bitNum {
					leaf := pos >> 16
					for fill := 0; fill < bitNum-nbits; fill++ {
						if table[leaf] == 0 {
							table[nextSymbol<<1] = 0
							table[(nextSymbol<<1)+1] = 0
							table[leaf] = nextSymbol
							nextSymbol++
						}
						leaf = table[leaf] << 1
						if (pos>>uint(15-fill))&1 == 1 {
							leaf++
						}
					}
					table[leaf] = sym
					pos += bitMask
					if pos > tableMask {
						return false
					}
				}
			}
			bitMask >>= 1
			bitNum++
		}
	}

	if pos == tableMask {
		return true
	}
	for sym := 0; sym < nsyms; sym++ {
		if length[sym] != 0 {
			return false
		}
	}
	return true
}

func (d *lzxDecoder) decompressBlock(bb *bitBuffer) {
	st := d.state
	for st.blockRemaining > 0 {
		mainElement := d.readHuffSymMaintree(bb)
		if mainElement < numChars {
			st.window[st.windowPosn] = byte(mainElement)
			st.windowPosn++
			st.blockRemaining--
			continue
		}

		mainElement -= numChars

		matchLength := mainElement & numPrimaryLengths
		if matchLength == numPrimaryLengths {
			matchLength += d.readHuffSymLentree(bb)
		}
		matchLength += minMatch

		matchOffset := mainElement >> 3

		if matchOffset > 2 {
			extra := extraBits[matchOffset]
			var verbatimBits, alignedBits int
			// The LZX "specification" says an aligned symbol is read only if
			// num_extra_bits > 3; in reality it is >= 3.
			if st.blockType == blockAligned && extra >= 3 {
				verbatimBits = bb.readBits(extra-3) << 3
				alignedBits = d.readHuffSymAligntree(bb)
			} else {
				verbatimBits = bb.readBits(extra)
				alignedBits = 0
			}

			matchOffset = positionBase[matchOffset] + verbatimBits + alignedBits - 2

			st.r2 = st.r1
			st.r1 = st.r0
			st.r0 = matchOffset
		} else if matchOffset == 0 {
			matchOffset = st.r0
		} else if matchOffset == 1 {
			matchOffset = st.r1
			st.r1 = st.r0
			st.r0 = matchOffset
		} else {
			matchOffset = st.r2
			st.r2 = st.r0
			st.r0 = matchOffset
		}

		rundest := st.windowPosn
		st.blockRemaining -= matchLength

		var runsrc int
		if st.windowPosn >= matchOffset {
			runsrc = rundest - matchOffset
		} else {
			runsrc = rundest + (st.windowSize - matchOffset)
			copyLength := matchOffset - st.windowPosn
			if copyLength < matchLength {
				matchLength -= copyLength
				st.windowPosn += copyLength
				for k := 0; k < copyLength; k++ {
					st.window[rundest] = st.window[runsrc]
					rundest++
					runsrc++
				}
				runsrc = 0
			}
		}

		st.windowPosn += matchLength

		for k := 0; k < matchLength; k++ {
			st.window[rundest] = st.window[runsrc]
			rundest++
			runsrc++
		}
	}
}

// decompressUncompressed copies an uncompressed block straight into the window.
func (d *lzxDecoder) decompressUncompressed(in *memReader) {
	st := d.state
	in.readInto(st.window[st.windowPosn : st.windowPosn+st.blockRemaining])
	st.windowPosn += st.blockRemaining
}

// leUint reads up to n little-endian bytes from b at off (missing bytes ignored).
func leUint(b []byte, off, n int) int {
	v := 0
	for k := 0; k < n; k++ {
		if off+k >= 0 && off+k < len(b) {
			v |= int(b[off+k]) << uint(8*k)
		}
	}
	return v
}

// binDecompressROM decompresses one LZX chunk into dst.
func binDecompressROM(readBuffer []byte, amount int, dst []byte) (int, int) {
	in := &memReader{data: readBuffer}
	windowSize := in.readLE(4)
	decompressedSize := in.readLE(4)
	in.skip(8) // 8 bytes we don't need

	if decompressedSize > len(dst) {
		return -1, 0
	}

	decoder, err := newLZXDecoder(windowSize)
	if err != nil {
		return -1, 0
	}
	out, status := decoder.decompress(in, amount, decompressedSize)
	if status != 0 {
		return status, 0
	}
	copy(dst[:decompressedSize], out)
	return status, decompressedSize
}

// ceDecompressROM decompresses a section of a file extracted from a Windows CE
func ceDecompressROM(readBuffer []byte, compressedSize int, decompressedBuffer []byte,
	uncompressedSize, skip, step, blocksize int) int {

	outputPosition := 0
	blockBits := 10
	if blocksize == 4096 {
		blockBits = 12
	}

	if step != 1 && step != 2 {
		return -1
	}

	if (skip&((1<<uint(blockBits))-1)) != 0 || compressedSize <= 2 {
		return -1
	}

	numBlocks := leUint(readBuffer, 0, 3)
	if numBlocks == 0 {
		numBlocks = 2
	} else {
		numBlocks = ((numBlocks - 1) >> uint(blockBits&0x1f)) + 2
	}

	currentPosition := numBlocks * 3
	nextPosition := skip >> uint(blockBits&0x1f)
	if !(currentPosition <= compressedSize && nextPosition < numBlocks) {
		return -1
	}

	if nextPosition != 0 {
		currentPosition = leUint(readBuffer, nextPosition*3, 3)
	}

	blocksize = 0
	compressedSize = currentPosition
	inputPosition := (nextPosition + 1) * 3
	for currentBlock := nextPosition + 1; currentBlock < numBlocks; currentBlock++ {
		if uncompressedSize == 0 {
			break
		}

		currentPosition = leUint(readBuffer, inputPosition, 3)
		inputPosition += 3

		if compressedSize > len(readBuffer) || outputPosition > len(decompressedBuffer) {
			return -1
		}
		status, bytesProcessed := binDecompressROM(
			readBuffer[compressedSize:],
			currentPosition-compressedSize,
			decompressedBuffer[outputPosition:],
		)
		if status != 0 {
			return -1
		}

		blocksize += bytesProcessed
		outputPosition += bytesProcessed * step
		uncompressedSize -= bytesProcessed
		compressedSize = currentPosition
	}

	return blocksize
}
