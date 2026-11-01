package agree_qy7

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

var le = binary.LittleEndian
var be = binary.BigEndian

var nkOkSignature = []byte{0x4E, 0x4B, 0x4F, 0x4B}
var sum4Signature = []byte{0x53, 0x55, 0x4D, 0x34}

const (
	VersionStringLength = 32
	RomFileNameLength   = 25
)

type NKOKHeader struct {
	RomSize       uint32
	Sum2          uint16
	RomFileName   string
	Sum4          uint32
	VersionString string
}

func CalculateSUM4(data *[]byte, size int) uint32 {
	d := *data
	var sum uint32
	for i := 0; i+4 <= size; i += 4 {
		sum += le.Uint32(d[i:])
	}
	return sum
}

func CalculateSUM2(data *[]byte, size int) uint16 {
	d := *data
	var sum uint32
	for i := 0; i < size; i += 1 {
		sum += uint32(d[i])
	}
	return uint16(sum & 0x0000FFFF)
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
		RomSize:       romSize,
		Sum2:          sum2Checksum,
		RomFileName:   string(bytes.TrimRight(data[22:22+RomFileNameLength], "\x00")),
		Sum4:          sum4Checksum,
		VersionString: string(bytes.TrimRight(data[80:80+VersionStringLength], "\x00")),
	}, rom, nil
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
