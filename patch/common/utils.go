package patcher_common

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

var le = binary.LittleEndian

var nkOkSignature = []byte{0x4E, 0x4B, 0x4F, 0x4B}
var sum4Signature = []byte{0x53, 0x55, 0x4D, 0x34}
var ececSignature = []byte{0x45, 0x43, 0x45, 0x43}

const (
	VersionStringLength  = 16
	RomFileNameLength    = 16
	nkHeaderSize         = 512
	CustomECECSum4Offset = 0x84
	CustomECECSum2Offset = 0x30
)

type NKOKHeader struct {
	RomSize        uint32
	Sum2           uint16
	RomFileName    string
	Sum4           uint32
	VersionString  string
	VersionString2 string
}

func ReplaceInPlace(buf []byte, old, new []byte) error {
	if len(old) != len(new) {
		return fmt.Errorf("old/new length mismatch: %d vs %d (in-place patch must keep size)", len(old), len(new))
	}
	i := bytes.Index(buf, old)
	if i < 0 {
		return errors.New("pattern not found")
	}
	copy(buf[i:i+len(new)], new)
	return nil
}

func CalculateSUM4(data *[]byte, size int) uint32 {
	d := *data
	var sum uint32
	for i := 0; i+4 <= size; i += 4 {
		sum += le.Uint32(d[i:])
	}
	return sum
}

func CalculateSUM4ForCustomECEC(buf []byte) uint32 {
	var s uint32

	hdr := make([]byte, nkHeaderSize)
	n := copy(hdr, buf)
	_ = n

	for i := 0x30; i < 0x36; i++ {
		hdr[i] = 0
	}
	for i := 0x84; i < 0x8C; i++ {
		hdr[i] = 0
	}
	for i := 0; i < nkHeaderSize; i += 4 {
		s += binary.LittleEndian.Uint32(hdr[i : i+4])
	}

	i := nkHeaderSize
	for ; i+4 <= len(buf); i += 4 {
		s += binary.LittleEndian.Uint32(buf[i : i+4])
	}
	if i < len(buf) {
		var tail [4]byte
		copy(tail[:], buf[i:])
		s += binary.LittleEndian.Uint32(tail[:])
	}
	return s
}

func CalculateSUM2(data *[]byte, size int) uint16 {
	d := *data
	var sum uint32
	for i := 0; i < size; i += 1 {
		sum += uint32(d[i])
	}
	return uint16(sum & 0x0000FFFF)
}

func CalculateSUM2ForCustomECEC(data []byte) uint16 {
	size := len(data)
	s := CalculateSUM2(&data, size)
	if size > 48 {
		s -= uint16(data[48])
	}
	if size > 49 {
		s -= uint16(data[49])
	}
	return s
}

func ParseNKOKROM(b *[]byte, size int64, skipValidation bool) (*NKOKHeader, []byte, error) {
	if b == nil {
		return nil, nil, errors.New("nil buffer")
	}
	data := *b

	if size < 512 || len(data) < 512 {
		return nil, nil, errors.New("NKOK header too short")
	}
	if !bytes.Equal(data[48:48+len(sum4Signature)], sum4Signature) {
		return nil, nil, errors.New("SUM4 signature not found")
	}
	if !bytes.Equal(data[508:508+len(nkOkSignature)], nkOkSignature) {
		return nil, nil, errors.New("NKOK ROM signature not found")
	}

	romSize := le.Uint32(data[0:4])
	if (romSize == 0 || uint64(romSize)+512 > uint64(len(data))) && !skipValidation {
		return nil, nil, errors.New("NKOK ROM size is invalid")
	}

	sum4Checksum := le.Uint32(data[52:56])
	sum2Checksum := le.Uint16(data[20:22])

	var rom []byte = nil

	if !skipValidation {
		rom = data[512 : 512+romSize]
		calculatedSum4 := CalculateSUM4(&rom, int(romSize))
		calculatedSum2 := CalculateSUM2(&rom, int(romSize))

		if calculatedSum4 != sum4Checksum {
			return nil, nil, fmt.Errorf("SUM4 mismatch: got %08X, calculated %08X", calculatedSum4, sum4Checksum)
		}
		if calculatedSum2 != sum2Checksum {
			return nil, nil, fmt.Errorf("SUM2 mismatch: got %04X, calculated %04X", calculatedSum2, sum2Checksum)
		}
	}

	return &NKOKHeader{
		RomSize:        romSize,
		Sum2:           sum2Checksum,
		RomFileName:    string(bytes.TrimRight(data[22:22+RomFileNameLength], "\x00")),
		Sum4:           sum4Checksum,
		VersionString:  string(bytes.TrimRight(data[80:80+VersionStringLength], "\x00")),
		VersionString2: string(bytes.TrimRight(data[96:96+VersionStringLength], "\x00")),
	}, rom, nil
}

func ParseCustomECECHDR(b *[]byte, size int64, onlyHeader bool) (*NKOKHeader, []byte, error) {
	if b == nil {
		return nil, nil, errors.New("nil buffer")
	}
	data := *b

	if size < 512 || len(data) < 512 {
		return nil, nil, errors.New("CustomECEC header too short")
	}
	if !bytes.Equal(data[0x80:0x80+len(sum4Signature)], sum4Signature) {
		return nil, nil, errors.New("SUM4 signature not found")
	}
	if !bytes.Equal(data[0x40:0x40+len(ececSignature)], ececSignature) {
		return nil, nil, errors.New("ECEC ROM signature not found")
	}

	romSize := le.Uint32(data[0x88:0x8C])
	sum4Checksum := le.Uint32(data[CustomECECSum4Offset : CustomECECSum4Offset+4])
	sum2Checksum := le.Uint16(data[CustomECECSum2Offset : CustomECECSum2Offset+2])

	if onlyHeader {
		return &NKOKHeader{
			RomSize:        romSize,
			Sum2:           sum2Checksum,
			RomFileName:    string(bytes.TrimRight(data[32:32+RomFileNameLength], "\x00")),
			Sum4:           sum4Checksum,
			VersionString:  string(bytes.TrimRight(data[80:80+VersionStringLength], "\x00")),
			VersionString2: string(bytes.TrimRight(data[96:96+VersionStringLength], "\x00")),
		}, nil, nil
	}
	if romSize == 0 || uint64(romSize) > uint64(len(data)) {
		return nil, nil, errors.New("ECEC ROM size is invalid")
	}

	rom := data[:romSize]

	calculatedSum4 := CalculateSUM4ForCustomECEC(rom)
	calculatedSum2 := CalculateSUM2ForCustomECEC(rom)

	if calculatedSum4 != sum4Checksum {
		return nil, nil, fmt.Errorf("SUM4 mismatch: got %08X, calculated %08X", calculatedSum4, sum4Checksum)
	}
	if calculatedSum2 != sum2Checksum {
		return nil, nil, fmt.Errorf("SUM2 mismatch: got %04X, calculated %04X", calculatedSum2, sum2Checksum)
	}

	return &NKOKHeader{
		RomSize:        romSize,
		Sum2:           sum2Checksum,
		RomFileName:    string(bytes.TrimRight(data[32:32+RomFileNameLength], "\x00")),
		Sum4:           sum4Checksum,
		VersionString:  string(bytes.TrimRight(data[80:80+VersionStringLength], "\x00")),
		VersionString2: string(bytes.TrimRight(data[96:96+VersionStringLength], "\x00")),
	}, rom, nil
}

func FixCustomECECChecksums(buf []byte) (sum4, sum2 uint32, err error) {
	if len(buf) < nkHeaderSize {
		return 0, 0, fmt.Errorf("buffer too small: %d bytes, need at least %d", len(buf), nkHeaderSize)
	}

	// First SUM4, because SUM2 includes SUM4 :)
	s4 := CalculateSUM4ForCustomECEC(buf)
	le.PutUint32(buf[0x84:], s4)

	s2 := CalculateSUM2ForCustomECEC(buf)
	le.PutUint16(buf[0x30:], s2)

	return s4, uint32(s2), nil
}

func PackNKOKROM(h *NKOKHeader, rom []byte) ([]byte, error) {
	if h == nil {
		return nil, errors.New("nil header")
	}
	if len(h.RomFileName) > RomFileNameLength {
		return nil, fmt.Errorf("RomFileName too long: %d > %d", len(h.RomFileName), RomFileNameLength)
	}
	if len(h.VersionString) > VersionStringLength {
		return nil, fmt.Errorf("VersionString too long: %d > %d", len(h.VersionString), VersionStringLength)
	}

	out := make([]byte, 512+len(rom))

	romSize := uint32(len(rom))
	sum4 := CalculateSUM4(&rom, len(rom))
	sum2 := CalculateSUM2(&rom, len(rom))

	le.PutUint32(out[0:4], romSize)
	le.PutUint16(out[20:22], sum2)
	copy(out[22:47], h.RomFileName)
	copy(out[48:48+len(sum4Signature)], sum4Signature)
	le.PutUint32(out[52:56], sum4)
	copy(out[80:112], h.VersionString)
	copy(out[508:508+len(nkOkSignature)], nkOkSignature)

	copy(out[512:], rom)
	return out, nil
}
