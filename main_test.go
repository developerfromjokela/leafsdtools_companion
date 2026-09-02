package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// bootSector builds a 512-byte boot sector carrying the given filesystem
// identifier at the given offset, plus the trailing 0x55AA signature.
func bootSector(offset int, id string) []byte {
	sec := make([]byte, 512)
	copy(sec[offset:], id)
	sec[510], sec[511] = 0x55, 0xAA
	return sec
}

// putEntry writes one MBR partition entry.
func putEntry(mbr []byte, idx int, typ byte, startLBA, sectors uint32) {
	e := mbr[446+idx*16 : 462+idx*16]
	e[4] = typ
	binary.LittleEndian.PutUint32(e[8:12], startLBA)
	binary.LittleEndian.PutUint32(e[12:16], sectors)
}

func TestDetectFsType(t *testing.T) {
	tests := []struct {
		name     string
		vbr      []byte
		wantType byte
		wantOk   bool
	}{
		{"exFAT", bootSector(3, "EXFAT   "), 0x07, true},
		{"NTFS", bootSector(3, "NTFS    "), 0x07, true},
		{"FAT32", bootSector(82, "FAT32   "), 0x0C, true},
		{"FAT16", bootSector(54, "FAT16   "), 0x0E, true},
		{"FAT12", bootSector(54, "FAT12   "), 0x01, true},
		{"no signature", make([]byte, 512), 0x00, false},
		{"unknown fs", bootSector(3, "WHATEVER"), 0x00, false},
		{"short buffer", make([]byte, 100), 0x00, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs, ok := detectFsType(tc.vbr)
			if ok != tc.wantOk || fs.want != tc.wantType {
				t.Errorf("detectFsType() = 0x%02X, %v; want 0x%02X, %v",
					fs.want, ok, tc.wantType, tc.wantOk)
			}
		})
	}
}

// TestAcceptsSynonyms guards the bytes that mean the same filesystem as the
// canonical one. They are not wrong, only spelled differently, so the tool must
// leave them alone instead of rewriting an entry it was not asked to touch.
func TestAcceptsSynonyms(t *testing.T) {
	tests := []struct {
		vbr      []byte
		accepted []byte
		rejected []byte
	}{
		{bootSector(3, "EXFAT   "), []byte{0x07, 0x17}, []byte{0x0C, 0x0B}},
		{bootSector(3, "NTFS    "), []byte{0x07, 0x17, 0x27}, []byte{0x0C}},
		{bootSector(82, "FAT32   "), []byte{0x0C, 0x0B, 0x1B, 0x1C}, []byte{0x07, 0x0E}},
		{bootSector(54, "FAT16   "), []byte{0x0E, 0x04, 0x06, 0x14, 0x16, 0x1E}, []byte{0x0C, 0x07}},
		{bootSector(54, "FAT12   "), []byte{0x01, 0x11}, []byte{0x0C, 0x0E}},
	}

	for _, tc := range tests {
		fs, ok := detectFsType(tc.vbr)
		if !ok {
			t.Fatalf("boot sector not recognised")
		}
		t.Run(fs.name, func(t *testing.T) {
			for _, b := range tc.accepted {
				if !fs.accepts(b) {
					t.Errorf("%s: type 0x%02X should be accepted as is", fs.name, b)
				}
			}
			for _, b := range tc.rejected {
				if fs.accepts(b) {
					t.Errorf("%s: type 0x%02X should be corrected to 0x%02X", fs.name, b, fs.want)
				}
			}
		})
	}
}

// TestCorrectPartitionTypes reproduces the layout of a Clarion card: every
// partition is declared 0x0C in the table, but the second one really holds
// exFAT and must come out as 0x07.
func TestCorrectPartitionTypes(t *testing.T) {
	const (
		p1LBA = 2048   // FAT32
		p2LBA = 4096   // exFAT, mistyped as FAT32 by Clarion
		p3LBA = 8192   // unrecognised content
		p4LBA = 999999 // past the end of the file
	)

	path := filepath.Join(t.TempDir(), "card.img")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	size := int64(p3LBA+1) * 512
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	for lba, sec := range map[uint32][]byte{
		p1LBA: bootSector(82, "FAT32   "),
		p2LBA: bootSector(3, "EXFAT   "),
		p3LBA: make([]byte, 512),
	} {
		if _, err := f.WriteAt(sec, int64(lba)*512); err != nil {
			t.Fatal(err)
		}
	}

	mbr := make([]byte, 512)
	putEntry(mbr, 0, 0x0C, p1LBA, 100)
	putEntry(mbr, 1, 0x0C, p2LBA, 100)
	putEntry(mbr, 2, 0x0C, p3LBA, 100)
	putEntry(mbr, 3, 0x0C, p4LBA, 100)

	var logged []string
	correctPartitionTypes(mbr, f, size, func(s string) { logged = append(logged, s) })

	want := []byte{0x0C, 0x07, 0x0C, 0x0C}
	for i, w := range want {
		if got := mbr[446+i*16+4]; got != w {
			t.Errorf("partition %d: type = 0x%02X, want 0x%02X\nlog:\n%v",
				i+1, got, w, logged)
		}
	}
}

// TestCorrectPartitionTypesSkipsEmptyEntries makes sure an all-zero table is
// left completely untouched.
func TestCorrectPartitionTypesSkipsEmptyEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.img")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(1024); err != nil {
		t.Fatal(err)
	}

	mbr := make([]byte, 512)
	correctPartitionTypes(mbr, f, 1024, func(string) {
		t.Error("empty partition entries should not be reported")
	})

	for i, b := range mbr {
		if b != 0 {
			t.Fatalf("byte %d changed to 0x%02X, table should be untouched", i, b)
		}
	}
}

// TestCorrectPartitionTypesKeepsSynonym checks the wiring: a FAT32 partition
// labelled 0x0B (CHS rather than LBA) is already correct and must survive the
// pass byte for byte.
func TestCorrectPartitionTypesKeepsSynonym(t *testing.T) {
	const lba = 2048

	path := filepath.Join(t.TempDir(), "chs.img")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	size := int64(lba+1) * 512
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(bootSector(82, "FAT32   "), lba*512); err != nil {
		t.Fatal(err)
	}

	mbr := make([]byte, 512)
	putEntry(mbr, 0, 0x0B, lba, 100)

	correctPartitionTypes(mbr, f, size, func(string) {})

	if got := mbr[446+4]; got != 0x0B {
		t.Errorf("type = 0x%02X, want 0x0B left untouched", got)
	}
}

// TestCorrectPartitionTypesUnknownSize covers a raw device whose size could not
// be determined — on macOS Stat() on /dev/rdiskN reports 0. The pass must still
// correct the entries it can read instead of skipping the whole table, and an
// entry that really is past the end simply fails to read and keeps its type.
func TestCorrectPartitionTypesUnknownSize(t *testing.T) {
	const (
		p1LBA = 2048   // exFAT, mistyped as FAT32
		p2LBA = 999999 // past the end of the file
	)

	path := filepath.Join(t.TempDir(), "device.img")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := f.Truncate(int64(p1LBA+1) * 512); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(bootSector(3, "EXFAT   "), p1LBA*512); err != nil {
		t.Fatal(err)
	}

	mbr := make([]byte, 512)
	putEntry(mbr, 0, 0x0C, p1LBA, 100)
	putEntry(mbr, 1, 0x0C, p2LBA, 100)

	var logged []string
	correctPartitionTypes(mbr, f, 0, func(s string) { logged = append(logged, s) })

	if got := mbr[446+4]; got != 0x07 {
		t.Errorf("partition 1: type = 0x%02X, want 0x07\nlog:\n%v", got, logged)
	}
	if got := mbr[446+16+4]; got != 0x0C {
		t.Errorf("partition 2: type = 0x%02X, want 0x0C left untouched\nlog:\n%v", got, logged)
	}
}
