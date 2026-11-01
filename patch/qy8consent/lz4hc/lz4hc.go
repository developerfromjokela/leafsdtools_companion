// Package lz4hc ports LZ4HC_compress_optimal (lz4 v1.10.0, single block), byte-identical to liblz4's level 12: Go's LZ4 libraries pack about 6% looser, enough to overrun a map-image chunk's allocated sectors.
package lz4hc

import "encoding/binary"

const (
	minMatch     = 4
	mlBits       = 4
	mlMask       = 1<<mlBits - 1
	runMask      = 1<<(8-mlBits) - 1
	lastLiterals = 5
	mfLimit      = 12
	distanceMax  = 65535

	hashLog   = 15
	hashSize  = 1 << hashLog
	chainSize = 1 << 16

	optNum           = 1 << 12
	trailingLiterals = 3

	// nbSearches and sufficientMax are k_clTable's level 12 entry (12 = LZ4HC_CLEVEL_MAX).
	nbSearches    = 16384
	sufficientMax = optNum - 1

	// prefixIdx offsets src[i] to index i+prefixIdx, as LZ4HC_init_internal does for a no-dictionary stream.
	prefixIdx = 1 << 16
)

func CompressBound(srcLen int) int {
	if srcLen <= 0 || srcLen > 0x7E000000 {
		return 0
	}
	return srcLen + srcLen/255 + 16
}

// Compress is equivalent to LZ4_compress_HC(..., 12).
func Compress(src []byte) []byte {
	dst := make([]byte, CompressBound(len(src)))
	return dst[:compress(src, dst)]
}

type match struct {
	off int
	len int
}

type optimal struct {
	price  int
	off    int
	mlen   int
	litlen int
}

type ctx struct {
	hashTable    [hashSize]uint32
	chainTable   [chainSize]uint16
	src          []byte
	nextToUpdate uint32
}

func hash4(v uint32) uint32 { return (v * 2654435761) >> (32 - hashLog) }

func read16(b []byte, i int) uint16 { return binary.LittleEndian.Uint16(b[i:]) }
func read32(b []byte, i int) uint32 { return binary.LittleEndian.Uint32(b[i:]) }

func count(src []byte, a, b, limit int) int {
	n := 0
	for a+n < limit && src[a+n] == src[b+n] {
		n++
	}
	return n
}

func countPattern(src []byte, p, end int, pattern uint32) int {
	var pb [4]byte
	binary.LittleEndian.PutUint32(pb[:], pattern)
	n := 0
	for p+n < end && src[p+n] == pb[n&3] {
		n++
	}
	return n
}

func countPatternBack(src []byte, p, low int, pattern uint32) int {
	var pb [4]byte
	binary.LittleEndian.PutUint32(pb[:], pattern)
	n := 0
	for p-n > low && src[p-n-1] == pb[3-(n&3)] {
		n++
	}
	return n
}

func (c *ctx) insert(target uint32) {
	for idx := c.nextToUpdate; idx < target; idx++ {
		h := hash4(read32(c.src, int(idx-prefixIdx)))
		delta := idx - c.hashTable[h]
		if delta > distanceMax {
			delta = distanceMax
		}
		c.chainTable[uint16(idx)] = uint16(delta)
		c.hashTable[h] = idx
	}
	c.nextToUpdate = target
}

// findMatch is LZ4HC_InsertAndGetWiderMatch, forward-search only: chain swapping jumps to a farther next link.
func (c *ctx) findMatch(ip, iHighLimit, minLen int) match {
	src := c.src
	ipIndex := uint32(ip) + prefixIdx
	lowestMatchIndex := uint32(prefixIdx)
	if prefixIdx+distanceMax+1 <= ipIndex {
		lowestMatchIndex = ipIndex - distanceMax
	}
	pattern := read32(src, ip)
	longest := minLen
	offset := 0
	attempts := nbSearches
	matchChainPos := uint32(0)
	patternTested, patternIsRun := false, false
	srcPatternLength := 0

	c.insert(ipIndex)
	matchIndex := c.hashTable[hash4(pattern)]

	for matchIndex >= lowestMatchIndex && attempts > 0 {
		attempts--
		matchLength := 0
		m := int(matchIndex - prefixIdx)

		if read16(src, ip+longest-1) == read16(src, m+longest-1) && read32(src, m) == pattern {
			matchLength = minMatch + count(src, ip+minMatch, m+minMatch, iHighLimit)
			if matchLength > longest {
				longest = matchLength
				offset = int(ipIndex - matchIndex)
			}
		}

		if matchLength == longest && matchIndex+uint32(longest) <= ipIndex {
			const trigger = 4
			dist := uint32(1)
			end := longest - minMatch + 1
			step, accel := 1, 1<<trigger
			for pos := 0; pos < end; pos += step {
				cand := uint32(c.chainTable[uint16(matchIndex+uint32(pos))])
				step = accel >> trigger
				accel++
				if cand > dist {
					dist = cand
					matchChainPos = uint32(pos)
					accel = 1 << trigger
				}
			}
			if dist > 1 {
				if dist > matchIndex {
					break
				}
				matchIndex -= dist
				continue
			}
		}

		if c.chainTable[uint16(matchIndex)] == 1 && matchChainPos == 0 {
			candidate := matchIndex - 1
			if !patternTested {
				patternTested = true
				patternIsRun = pattern&0xFFFF == pattern>>16 && pattern&0xFF == pattern>>24
				if patternIsRun {
					srcPatternLength = countPattern(src, ip+4, iHighLimit, pattern) + 4
				}
			}
			if patternIsRun && candidate >= lowestMatchIndex {
				mp := int(candidate - prefixIdx)
				if read32(src, mp) == pattern {
					forward := countPattern(src, mp+4, iHighLimit, pattern) + 4
					back := countPatternBack(src, mp, 0, pattern)
					if low := candidate - uint32(back); low < lowestMatchIndex {
						back = int(candidate - lowestMatchIndex)
					}
					segment := back + forward
					if segment >= srcPatternLength && forward <= srcPatternLength {
						matchIndex = candidate + uint32(forward) - uint32(srcPatternLength)
					} else {
						matchIndex = candidate - uint32(back)
						maxML := segment
						if srcPatternLength < maxML {
							maxML = srcPatternLength
						}
						if longest < maxML {
							if ipIndex-matchIndex > distanceMax {
								break
							}
							longest = maxML
							offset = int(ipIndex - matchIndex)
						}
						next := uint32(c.chainTable[uint16(matchIndex)])
						if next > matchIndex {
							break
						}
						matchIndex -= next
					}
					continue
				}
			}
		}

		matchIndex -= uint32(c.chainTable[uint16(matchIndex+matchChainPos)])
	}

	if longest <= minLen {
		return match{}
	}
	return match{off: offset, len: longest}
}

func literalsPrice(litlen int) int {
	price := litlen
	if litlen >= runMask {
		price += 1 + (litlen-runMask)/255
	}
	return price
}

func sequencePrice(litlen, mlen int) int {
	price := 3 + literalsPrice(litlen) // token + 16-bit offset
	if mlen >= mlMask+minMatch {
		price += 1 + (mlen-(mlMask+minMatch))/255
	}
	return price
}

func encodeSeq(dst []byte, op int, src []byte, ip, anchor *int, matchLength, offset int) int {
	token := op
	op++

	length := *ip - *anchor
	if length >= runMask {
		dst[token] = runMask << mlBits
		for n := length - runMask; ; {
			if n >= 255 {
				dst[op] = 255
				op++
				n -= 255
				continue
			}
			dst[op] = byte(n)
			op++
			break
		}
	} else {
		dst[token] = byte(length << mlBits)
	}
	op += copy(dst[op:], src[*anchor:*anchor+length])

	binary.LittleEndian.PutUint16(dst[op:], uint16(offset))
	op += 2

	length = matchLength - minMatch
	if length >= mlMask {
		dst[token] += mlMask
		length -= mlMask
		for ; length >= 510; length -= 510 {
			dst[op], dst[op+1] = 255, 255
			op += 2
		}
		if length >= 255 {
			length -= 255
			dst[op] = 255
			op++
		}
		dst[op] = byte(length)
		op++
	} else {
		dst[token] += byte(length)
	}

	*ip += matchLength
	*anchor = *ip
	return op
}

func compress(src, dst []byte) int {
	c := &ctx{src: src, nextToUpdate: prefixIdx}
	iend := len(src)
	mflimit := iend - mfLimit
	matchlimit := iend - lastLiterals
	ip, anchor, op := 0, 0, 0
	var opt [optNum + trailingLiterals]optimal

	for ip <= mflimit {
		llen := ip - anchor
		first := c.findMatch(ip, matchlimit, minMatch-1)
		if first.len == 0 {
			ip++
			continue
		}
		if first.len > sufficientMax {
			op = encodeSeq(dst, op, src, &ip, &anchor, first.len, first.off)
			continue
		}

		for rPos := 0; rPos < minMatch; rPos++ {
			opt[rPos] = optimal{price: literalsPrice(llen + rPos), mlen: 1, litlen: llen + rPos}
		}
		for mlen := minMatch; mlen <= first.len; mlen++ {
			opt[mlen] = optimal{price: sequencePrice(llen, mlen), off: first.off, mlen: mlen, litlen: llen}
		}
		lastMatchPos := first.len
		addTrailing := func() {
			for addLit := 1; addLit <= trailingLiterals; addLit++ {
				opt[lastMatchPos+addLit] = optimal{
					price:  opt[lastMatchPos].price + literalsPrice(addLit),
					mlen:   1,
					litlen: addLit,
				}
			}
		}
		addTrailing()

		bestMlen, bestOff := 0, 0
		cur := 1
		immediate := false
		for ; cur < lastMatchPos; cur++ {
			if ip+cur > mflimit {
				break
			}
			if opt[cur+1].price <= opt[cur].price &&
				opt[cur+minMatch].price < opt[cur].price+3 {
				continue
			}
			nm := c.findMatch(ip+cur, matchlimit, minMatch-1)
			if nm.len == 0 {
				continue
			}
			if nm.len > sufficientMax || nm.len+cur >= optNum {
				bestMlen, bestOff = nm.len, nm.off
				lastMatchPos = cur + 1
				immediate = true
				break
			}

			baseLitlen := opt[cur].litlen
			for litlen := 1; litlen < minMatch; litlen++ {
				price := opt[cur].price - literalsPrice(baseLitlen) + literalsPrice(baseLitlen+litlen)
				if pos := cur + litlen; price < opt[pos].price {
					opt[pos] = optimal{price: price, mlen: 1, litlen: baseLitlen + litlen}
				}
			}
			for ml := minMatch; ml <= nm.len; ml++ {
				pos := cur + ml
				var price, ll int
				if opt[cur].mlen == 1 {
					ll = opt[cur].litlen
					if cur > ll {
						price = opt[cur-ll].price
					}
					price += sequencePrice(ll, ml)
				} else {
					price = opt[cur].price + sequencePrice(0, ml)
				}
				if pos > lastMatchPos+trailingLiterals || price <= opt[pos].price {
					if ml == nm.len && lastMatchPos < pos {
						lastMatchPos = pos
					}
					opt[pos] = optimal{price: price, off: nm.off, mlen: ml, litlen: ll}
				}
			}
			addTrailing()
		}

		if !immediate {
			bestMlen = opt[lastMatchPos].mlen
			bestOff = opt[lastMatchPos].off
			cur = lastMatchPos - bestMlen
		}

		pos, selML, selOff := cur, bestMlen, bestOff
		for {
			nextML, nextOff := opt[pos].mlen, opt[pos].off
			opt[pos].mlen, opt[pos].off = selML, selOff
			selML, selOff = nextML, nextOff
			if nextML > pos {
				break
			}
			pos -= nextML
		}

		for rPos := 0; rPos < lastMatchPos; {
			ml, off := opt[rPos].mlen, opt[rPos].off
			if ml == 1 {
				ip++
				rPos++
				continue
			}
			rPos += ml
			op = encodeSeq(dst, op, src, &ip, &anchor, ml, off)
		}
	}

	lastRun := iend - anchor
	if lastRun >= runMask {
		dst[op] = runMask << mlBits
		op++
		for n := lastRun - runMask; ; {
			if n >= 255 {
				dst[op] = 255
				op++
				n -= 255
				continue
			}
			dst[op] = byte(n)
			op++
			break
		}
	} else {
		dst[op] = byte(lastRun << mlBits)
		op++
	}
	op += copy(dst[op:], src[anchor:])
	return op
}
