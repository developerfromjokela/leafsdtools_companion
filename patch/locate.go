package patch

import (
	"LeafSDTools_Companion/patch/c_lz4"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// decodeArmImm декодує значення константи з ARM інструкції (movw або data-processing immediate).
func decodeArmImm(w uint32) (uint32, bool) {
	if (w & 0xfff00000) == 0xe3000000 { // movw rd, #imm16
		return ((w >> 4) & 0xf000) | (w & 0xfff), true
	} else if (w & 0x0e000000) == 0x02000000 { // Data-processing immediate (mov, cmp, add, sub тощо)
		rot := (w >> 8) & 0xf
		val := w & 0xff
		shift := rot * 2
		res := ((val >> shift) | (val << (32 - shift))) & 0xffffffff
		return res, true
	}
	return 0, false
}

// SectionInfo містить інформацію про секцію модуля у WinCE XIP.
type SectionInfo struct {
	Index   int
	VSize   uint32
	RVA     uint32
	PSize   uint32
	DataPtr uint32
	Real    uint32
	Flags   uint32
}

// XipParser парсить плоский XIP образ WinCE.
type XipParser struct {
	data      []byte
	base      int
	physfirst uint32
	physlast  uint32
	nummods   uint32
	toc       int
}

func newXipParser(data []byte) (*XipParser, error) {
	idx := bytes.Index(data, []byte("ECEC"))
	if idx < 0 || idx < 0x40 {
		return nil, errors.New("ECEC signature not found in XIP")
	}
	base := idx - 0x40
	romhdrVA := binary.LittleEndian.Uint32(data[base+0x44 : base+0x48])

	var ro int = -1
	var pf uint32
	for candPF := uint32(0x80000000); candPF < 0x90000000; candPF += 0x10000 {
		off := int(romhdrVA - candPF + uint32(base))
		if off < 0 || off+0x60 > len(data) {
			continue
		}
		if binary.LittleEndian.Uint32(data[off+8:off+12]) == candPF {
			nummods := binary.LittleEndian.Uint32(data[off+0x10 : off+0x14])
			physlast := binary.LittleEndian.Uint32(data[off+0x0c : off+0x10])
			if nummods > 0 && nummods < 2000 && candPF < physlast {
				ro = off
				pf = candPF
				break
			}
		}
	}
	if ro < 0 {
		return nil, errors.New("failed to consistently locate ROMHDR")
	}

	xp := &XipParser{
		data:      data,
		base:      base,
		physfirst: pf,
		physlast:  binary.LittleEndian.Uint32(data[ro+0x0c : ro+0x10]),
		nummods:   binary.LittleEndian.Uint32(data[ro+0x10 : ro+0x14]),
		toc:       ro + 0x54,
	}
	return xp, nil
}

func (xp *XipParser) fo(va uint32) int {
	return int(va - xp.physfirst + uint32(xp.base))
}

func (xp *XipParser) findModule(targetName string) (int, error) {
	for i := uint32(0); i < xp.nummods; i++ {
		e := xp.toc + int(i)*32
		nameVA := binary.LittleEndian.Uint32(xp.data[e+0x10 : e+0x14])
		nameFO := xp.fo(nameVA)
		if nameFO < 0 || nameFO >= len(xp.data) {
			continue
		}
		raw := xp.data[nameFO:]
		zeroIdx := bytes.IndexByte(raw, 0)
		if zeroIdx > 0 {
			name := string(raw[:zeroIdx])
			if strings.EqualFold(name, targetName) {
				return e, nil
			}
		}
	}
	return 0, fmt.Errorf("module %s not found in XIP", targetName)
}

func (xp *XipParser) moduleSections(entryOffset int) ([]SectionInfo, uint32, error) {
	e32VA := binary.LittleEndian.Uint32(xp.data[entryOffset+0x14 : entryOffset+0x18])
	o32VA := binary.LittleEndian.Uint32(xp.data[entryOffset+0x18 : entryOffset+0x1c])
	e32FO := xp.fo(e32VA)
	o32FO := xp.fo(o32VA)

	if e32FO < 0 || e32FO+2 > len(xp.data) || o32FO < 0 {
		return nil, 0, errors.New("invalid e32/o32 offsets")
	}

	objcnt := int(binary.LittleEndian.Uint16(xp.data[e32FO : e32FO+2]))
	var secs []SectionInfo
	for k := 0; k < objcnt; k++ {
		sOff := o32FO + k*24
		if sOff+24 > len(xp.data) {
			break
		}
		vsize := binary.LittleEndian.Uint32(xp.data[sOff : sOff+4])
		rva := binary.LittleEndian.Uint32(xp.data[sOff+4 : sOff+8])
		psize := binary.LittleEndian.Uint32(xp.data[sOff+8 : sOff+12])
		dataptr := binary.LittleEndian.Uint32(xp.data[sOff+12 : sOff+16])
		real := binary.LittleEndian.Uint32(xp.data[sOff+16 : sOff+20])
		flags := binary.LittleEndian.Uint32(xp.data[sOff+20 : sOff+24])

		secs = append(secs, SectionInfo{
			Index:   k,
			VSize:   vsize,
			RVA:     rva,
			PSize:   psize,
			DataPtr: dataptr,
			Real:    real,
			Flags:   flags,
		})
	}
	return secs, e32VA, nil
}

// FindNBImage шукає NB/MTCP заголовок у файлі образу або на картці.
func FindNBImage(data []byte) (int64, string, int64, error) {
	pos := 0
	for {
		idx := bytes.Index(data[pos:], []byte("MTCP"))
		if idx < 0 {
			break
		}
		mtOff := pos + idx
		if mtOff >= 0x200 {
			nbOff := mtOff - 0x200
			sum4 := data[nbOff+0x30 : nbOff+0x34]
			if bytes.Equal(sum4, []byte("SUM4")) {
				nChunks := binary.LittleEndian.Uint32(data[mtOff+4 : mtOff+8])
				if nChunks > 0 && nChunks < 100 {
					name := strings.TrimRight(string(data[nbOff+0x16:nbOff+0x28]), "\x00")
					modLen := int64(binary.LittleEndian.Uint32(data[nbOff:nbOff+4])) + 0x200
					return int64(nbOff), name, modLen, nil
				}
			}
		}
		pos = mtOff + 1
	}
	return 0, "", 0, errors.New("MTCP image header not found")
}

// UnpackMTCPToFlat розпаковує MTCP-контейнер у плоский XIP образ.
func UnpackMTCPToFlat(data []byte, nbOff int64) ([]byte, error) {
	mt := int(nbOff + 0x200)
	if mt+0x200 > len(data) || !bytes.Equal(data[mt:mt+4], []byte("MTCP")) {
		return nil, errors.New("invalid MTCP header")
	}

	n := int(binary.LittleEndian.Uint32(data[mt+4 : mt+8]))
	pos := mt + 0x200
	var out bytes.Buffer

	for c := 0; c < n; c++ {
		entryOff := mt + 0x20 + c*0x20
		secs := int(binary.LittleEndian.Uint32(data[entryOff : entryOff+4]))
		usize := int(binary.LittleEndian.Uint32(data[entryOff+4 : entryOff+8]))
		csize := int(binary.LittleEndian.Uint32(data[entryOff+8 : entryOff+12]))

		if pos+csize > len(data) {
			return nil, fmt.Errorf("chunk %d data truncated", c)
		}
		raw, err := c_lz4.Decompress(data[pos:pos+csize], usize)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress chunk %d: %w", c, err)
		}
		out.Write(raw)
		pos += secs * 512
	}

	nbLen := int(binary.LittleEndian.Uint32(data[nbOff : nbOff+4]))
	tailEnd := int(nbOff) + 0x200 + nbLen
	if tailEnd <= len(data) && pos < tailEnd {
		out.Write(data[pos:tailEnd])
	}

	return out.Bytes(), nil
}

// LocateBuildConfig виконує динамічний пошук усіх полів авто-згоди у вихідному образі або пласкій XIP.
func LocateBuildConfig(rawOrFlat []byte) (*BuildConfig, error) {
	var flatXIP []byte
	var buildName string
	var modLen int64

	nbOff, name, length, err := FindNBImage(rawOrFlat)
	if err == nil {
		buildName = name
		modLen = length
		flat, uErr := UnpackMTCPToFlat(rawOrFlat, nbOff)
		if uErr != nil {
			return nil, fmt.Errorf("failed to unpack MTCP: %w", uErr)
		}
		flatXIP = flat
	} else {
		// Перевіримо, чи це вже плоский XIP
		if bytes.Contains(rawOrFlat[:min(0x1000, len(rawOrFlat))], []byte("ECEC")) {
			flatXIP = rawOrFlat
			buildName = "UNKNOWN"
			modLen = int64(len(rawOrFlat))
		} else {
			return nil, errors.New("neither MTCP nor flat XIP found")
		}
	}

	xp, err := newXipParser(flatXIP)
	if err != nil {
		return nil, fmt.Errorf("failed to parse XIP: %w", err)
	}

	sccEntry, err := xp.findModule("ScreenStateCC.dll")
	if err != nil {
		return nil, err
	}

	secs, e32VA, err := xp.moduleSections(sccEntry)
	if err != nil || len(secs) == 0 {
		return nil, errors.New("failed to read ScreenStateCC.dll sections")
	}

	sec0 := secs[0]
	sec0VA := sec0.Real
	sec0File := uint32(xp.fo(sec0.DataPtr))
	sec0Size := int(sec0.VSize)

	if int(sec0File)+sec0Size > len(flatXIP) {
		return nil, errors.New("sec0 truncated in XIP")
	}
	sec0Data := flatXIP[sec0File : int(sec0File)+sec0Size]

	// Парсимо імпорт ScreenState.dll
	e32FO := xp.fo(e32VA)
	impRVA := binary.LittleEndian.Uint32(flatXIP[e32FO+0x2c : e32FO+0x30])
	ordToIAT := make(map[uint16]uint32)

	for _, sec := range secs {
		if sec.RVA <= impRVA && impRVA < sec.RVA+sec.VSize {
			descFO := xp.fo(sec.DataPtr) + int(impRVA-sec.RVA)
			cur := descFO
			for {
				oft := binary.LittleEndian.Uint32(flatXIP[cur : cur+4])
				nameRVA := binary.LittleEndian.Uint32(flatXIP[cur+12 : cur+16])
				ft := binary.LittleEndian.Uint32(flatXIP[cur+16 : cur+20])
				if ft == 0 && nameRVA == 0 {
					break
				}
				dllName := ""
				for _, sec2 := range secs {
					if sec2.RVA <= nameRVA && nameRVA < sec2.RVA+sec2.VSize {
						nFO := xp.fo(sec2.DataPtr) + int(nameRVA-sec2.RVA)
						raw := flatXIP[nFO : nFO+32]
						z := bytes.IndexByte(raw, 0)
						if z > 0 {
							dllName = string(raw[:z])
						}
						break
					}
				}
				if strings.EqualFold(dllName, "ScreenState.dll") {
					for _, secILT := range secs {
						if secILT.RVA <= oft && oft < secILT.RVA+secILT.VSize {
							iltFO := xp.fo(secILT.DataPtr) + int(oft-secILT.RVA)
							var iatSec *SectionInfo
							for sIdx := range secs {
								if secs[sIdx].RVA <= ft && ft < secs[sIdx].RVA+secs[sIdx].VSize {
									iatSec = &secs[sIdx]
									break
								}
							}
							if iatSec != nil {
								idx := 0
								for {
									val := binary.LittleEndian.Uint32(flatXIP[iltFO+idx*4 : iltFO+idx*4+4])
									if val == 0 {
										break
									}
									if val&0x80000000 != 0 {
										ordNum := uint16(val & 0xffff)
										iatVA := iatSec.Real + (ft - iatSec.RVA) + uint32(idx*4)
										ordToIAT[ordNum] = iatVA
									}
									idx++
								}
							}
							break
						}
					}
				}
				cur += 20
			}
			break
		}
	}

	// Знаходимо thunk-и
	targetOrds := map[string]uint16{
		"GetContext": 16,
		"SetVar":     38,
		"CheckVar":   68,
		"GetState":   40,
		"GetState2":  87,
		"EvHandler":  39,
		"ExecFn":     77,
		"SetTimer":   57,
	}
	thunks := make(map[string]uint32)
	for fname, o := range targetOrds {
		iat, ok := ordToIAT[o]
		if !ok {
			continue
		}
		pat := make([]byte, 16)
		binary.LittleEndian.PutUint32(pat[0:4], 0xe59fc004)
		binary.LittleEndian.PutUint32(pat[4:8], 0xe59cc000)
		binary.LittleEndian.PutUint32(pat[8:12], 0xe12fff1c)
		binary.LittleEndian.PutUint32(pat[12:16], iat)

		pos := bytes.Index(sec0Data, pat)
		if pos >= 0 {
			thunks[fname] = sec0VA + uint32(pos)
		}
	}

	readPoolStr := func(poolAddr uint32) string {
		if poolAddr < sec0VA || int(poolAddr-sec0VA)+4 > sec0Size {
			return ""
		}
		sPtr := binary.LittleEndian.Uint32(sec0Data[poolAddr-sec0VA : poolAddr-sec0VA+4])
		if sPtr < sec0VA || int(sPtr-sec0VA)+16 > sec0Size {
			return ""
		}
		raw := sec0Data[sPtr-sec0VA : sPtr-sec0VA+16]
		z := bytes.IndexByte(raw, 0)
		if z > 0 {
			return string(raw[:z])
		}
		return ""
	}

	// 1. Параметри I Agree: VarAgree, Ctrl, Notify, redir_event, agree_event
	var varAgree, ctrlID, notifyID uint32
	var agreeEvent uint32
	ctrlID = 25

	execThunk, hasExec := thunks["ExecFn"]
	setvarThunk, hasSetVar := thunks["SetVar"]
	evThunk, hasEv := thunks["EvHandler"]

	if hasExec && hasSetVar {
		var redirEvent uint32
		var execVA uint32
		for i := 0x40; i < sec0Size-0x40; i += 4 {
			cva := sec0VA + uint32(i)
			blTarget := 0xeb000000 | (((execThunk - (cva + 8)) >> 2) & 0xffffff)
			if binary.LittleEndian.Uint32(sec0Data[i:i+4]) == blTarget {
				for step := 4; step < 20; step += 4 {
					if binary.LittleEndian.Uint32(sec0Data[i-step:i-step+4]) == 0xe3a01019 { // mov r1, #25
						wNot := binary.LittleEndian.Uint32(sec0Data[i-step-4 : i-step])
						if nVal, ok := decodeArmImm(wNot); ok {
							for step2 := step + 8; step2 < step + 40; step2 += 4 {
								wSv := binary.LittleEndian.Uint32(sec0Data[i-step2 : i-step2+4])
								svTarget := 0xeb000000 | (((setvarThunk - (cva - uint32(step2) + 8)) >> 2) & 0xffffff)
								if wSv == svTarget {
									for step3 := 4; step3 < 16; step3 += 4 {
										wVa := binary.LittleEndian.Uint32(sec0Data[i-step2-step3 : i-step2-step3+4])
										if vAgr, ok := decodeArmImm(wVa); ok {
											varAgree = vAgr
											notifyID = nVal
											execVA = cva

											// Найближчий CMP перед блоком
											for stepCmp := step2 + 4; stepCmp < step2+0x40; stepCmp += 4 {
												wCmp := binary.LittleEndian.Uint32(sec0Data[i-stepCmp : i-stepCmp+4])
												if (wCmp & 0x0ff00000) == 0x03500000 {
													if imm, ok := decodeArmImm(wCmp); ok {
														redirEvent = imm
														break
													}
												} else if (wCmp & 0x0ff00000) == 0x01500000 {
													wMov := binary.LittleEndian.Uint32(sec0Data[i-stepCmp-4 : i-stepCmp])
													if imm, ok := decodeArmImm(wMov); ok {
														redirEvent = imm
														break
													}
												}
											}
											break
										}
									}
									break
								}
							}
						}
						break
					}
				}
				if execVA != 0 {
					break
				}
			}
		}

		if redirEvent != 0 && hasEv {
			for i := 0x40; i < sec0Size-0x40; i += 4 {
				cva := sec0VA + uint32(i)
				blTarget := 0xeb000000 | (((evThunk - (cva + 8)) >> 2) & 0xffffff)
				if binary.LittleEndian.Uint32(sec0Data[i:i+4]) == blTarget {
					wR1 := binary.LittleEndian.Uint32(sec0Data[i-8 : i-4])
					if imm, ok := decodeArmImm(wR1); ok && imm == redirEvent {
						for stepCmp := 12; stepCmp < 0x80; stepCmp += 4 {
							wCmp := binary.LittleEndian.Uint32(sec0Data[i-stepCmp : i-stepCmp+4])
							if (wCmp&0x0ff00000) == 0x01500000 || (wCmp&0x0ff00000) == 0x03500000 {
								wEv := binary.LittleEndian.Uint32(sec0Data[i-stepCmp-4 : i-stepCmp])
								if evVal, ok := decodeArmImm(wEv); ok {
									agreeEvent = evVal
									break
								}
								if evVal, ok := decodeArmImm(wCmp); ok {
									agreeEvent = evVal
									break
								}
							}
						}
						if agreeEvent != 0 {
							break
						}
					}
				}
			}
		}
	}

	// 2. TimerConfig та VarStartup
	var timerConfig *TimerConfig
	var varStartup uint32
	ctxThunk, hasCtx := thunks["GetContext"]
	chkThunk, hasChk := thunks["CheckVar"]

	if hasChk && hasSetVar && hasCtx {
		for i := 0; i < sec0Size-0x80; i += 4 {
			cva := sec0VA + uint32(i)
			if binary.LittleEndian.Uint32(sec0Data[i:i+4]) == (0xeb000000 | (((ctxThunk - (cva + 8)) >> 2) & 0xffffff)) {
				if binary.LittleEndian.Uint32(sec0Data[i+0x14:i+0x18]) == (0xeb000000 | (((chkThunk - (cva + 0x14 + 8)) >> 2) & 0xffffff)) {
					if binary.LittleEndian.Uint32(sec0Data[i+0x28:i+0x2c]) == (0xeb000000 | (((ctxThunk - (cva + 0x28 + 8)) >> 2) & 0xffffff)) {
						if binary.LittleEndian.Uint32(sec0Data[i+0x3c:i+0x40]) == (0xeb000000 | (((setvarThunk - (cva + 0x3c + 8)) >> 2) & 0xffffff)) {
							ldrF := binary.LittleEndian.Uint32(sec0Data[i+0x08 : i+0x0c])
							if (ldrF & 0xfffff000) != 0xe59f2000 {
								continue
							}
							pfalseVA := cva + 0x08 + 8 + (ldrF & 0xfff)

							ldrT := binary.LittleEndian.Uint32(sec0Data[i+0x30 : i+0x34])
							if (ldrT & 0xfffff000) != 0xe59f2000 {
								continue
							}
							ptrueVA := cva + 0x30 + 8 + (ldrT & 0xfff)

							sf := readPoolStr(pfalseVA)
							st := readPoolStr(ptrueVA)
							if sf == "false" && st == "true" {
								wSt := binary.LittleEndian.Uint32(sec0Data[i+0x0c : i+0x10])
								if vSt, ok := decodeArmImm(wSt); ok && vSt > 500 {
									bTail := binary.LittleEndian.Uint32(sec0Data[i+0x48 : i+0x4c])
									var tailTimer uint32
									if (bTail & 0xff000000) == 0xea000000 {
										imm24 := int32(bTail & 0x00ffffff)
										if imm24&0x00800000 != 0 {
											imm24 -= 0x01000000
										}
										tailTimer = uint32(int32(cva+0x48+8) + (imm24 << 2))
									}

									var stockTimer []uint32
									for sIdx := 0; sIdx < 19; sIdx++ {
										stockTimer = append(stockTimer, binary.LittleEndian.Uint32(sec0Data[i+sIdx*4:i+sIdx*4+4]))
									}

									varStartup = vSt
									timerConfig = &TimerConfig{
										VA:         cva,
										Tail:       tailTimer,
										PTrue:      ptrueVA,
										PFalse:     pfalseVA,
										VarStartup: vSt,
										Event:      agreeEvent,
										Stock:      stockTimer,
									}
									break
								}
							}
						}
					}
				}
			}
		}
	}

	// 3. SkipConfig
	var skipConfig *SkipConfig
	stThunk, hasSt := thunks["GetState"]

	if hasCtx && hasSetVar && hasSt && hasEv {
		for i := 0x100; i < sec0Size-0x80; i += 4 {
			cva := sec0VA + uint32(i)
			if binary.LittleEndian.Uint32(sec0Data[i:i+4]) == (0xeb000000 | (((ctxThunk - (cva + 8)) >> 2) & 0xffffff)) {
				if binary.LittleEndian.Uint32(sec0Data[i+0x14:i+0x18]) == (0xeb000000 | (((setvarThunk - (cva + 0x14 + 8)) >> 2) & 0xffffff)) {
					if binary.LittleEndian.Uint32(sec0Data[i+0x24:i+0x28]) == (0xeb000000 | (((stThunk - (cva + 0x24 + 8)) >> 2) & 0xffffff)) {
						if binary.LittleEndian.Uint32(sec0Data[i+0x34:i+0x38]) == (0xeb000000 | (((evThunk - (cva + 0x34 + 8)) >> 2) & 0xffffff)) {
							if binary.LittleEndian.Uint32(sec0Data[i+0x64:i+0x68]) == (0xeb000000 | (((evThunk - (cva + 0x64 + 8)) >> 2) & 0xffffff)) {
								ldrP := binary.LittleEndian.Uint32(sec0Data[i+0x08 : i+0x0c])
								if (ldrP & 0xfffff000) != 0xe59f2000 {
									continue
								}
								poolFalse := cva + 0x08 + 8 + (ldrP & 0xfff)
								if readPoolStr(poolFalse) != "false" {
									continue
								}

								var ptrueVA uint32
								for back := 0x50; back < 0xd0; back += 4 {
									bVA := cva - uint32(back)
									bIdx := i - back
									ldrPt := binary.LittleEndian.Uint32(sec0Data[bIdx+0x08 : bIdx+0x0c])
									if (ldrPt & 0xfffff000) == 0xe59f2000 {
										candPt := bVA + 0x08 + 8 + (ldrPt & 0xfff)
										diff := int(candPt) - int(poolFalse)
										if diff < 0 {
											diff = -diff
										}
										if diff <= 8 && readPoolStr(candPt) == "true" {
											evC2, ok2 := decodeArmImm(binary.LittleEndian.Uint32(sec0Data[i-12 : i-8]))
											evC1, ok1 := decodeArmImm(binary.LittleEndian.Uint32(sec0Data[bIdx-12 : bIdx-8]))
											if ok1 && ok2 && evC1 == evC2+1 {
												ptrueVA = candPt
												break
											}
										}
									}
								}

								if ptrueVA == 0 {
									continue
								}

								vSk, _ := decodeArmImm(binary.LittleEndian.Uint32(sec0Data[i+0x0c : i+0x10]))
								act, _ := decodeArmImm(binary.LittleEndian.Uint32(sec0Data[i+0x2c : i+0x30]))

								bTail := binary.LittleEndian.Uint32(sec0Data[i+0x70 : i+0x74])
								var tailVA uint32
								if (bTail & 0xff000000) == 0xea000000 {
									imm24 := int32(bTail & 0x00ffffff)
									if imm24&0x00800000 != 0 {
										imm24 -= 0x01000000
									}
									tailVA = uint32(int32(cva+0x70+8) + (imm24 << 2))
								}

								var stockWords []uint32
								for sIdx := 0; sIdx < 29; sIdx++ {
									stockWords = append(stockWords, binary.LittleEndian.Uint32(sec0Data[i+sIdx*4:i+sIdx*4+4]))
								}

								skipConfig = &SkipConfig{
									VA:         cva,
									Tail:       tailVA,
									PTrue:      ptrueVA,
									VarSkip:    vSk,
									VarAgree:   varAgree,
									VarStartup: varStartup,
									Action:     act,
									Ctrl:       ctrlID,
									Notify:     notifyID,
									Stock:      stockWords,
								}
								break
							}
						}
					}
				}
			}
		}
	}

	b := &BuildConfig{
		Name:       buildName,
		ModLen:     modLen,
		Sec0File:   sec0File,
		Sec0VA:     sec0VA,
		GetContext: thunks["GetContext"],
		SetVar:     thunks["SetVar"],
		CheckVar:   thunks["CheckVar"],
		GetState:   thunks["GetState"],
		GetState2:  thunks["GetState2"],
		EvHandler:  thunks["EvHandler"],
		ExecFn:     thunks["ExecFn"],
		SetTimer:   thunks["SetTimer"],
		Skip:       skipConfig,
		Timer:      timerConfig,
	}

	return b, nil
}
