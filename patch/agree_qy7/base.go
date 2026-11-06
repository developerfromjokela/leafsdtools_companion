package agree_qy7

import (
	"LeafSDTools_Companion/patch"
	"LeafSDTools_Companion/patch/common"
	_ "embed"
	"errors"
	"fmt"
)

// IMPL BasePatch

func applyPatch(f patch.ReadWriterAt, size int64, log func(string)) error {
	nb00Header := make([]byte, 512)
	nb01Header := make([]byte, 512)
	nBytes, err := f.ReadAt(nb00Header, patcher_common.QY7nb00Offset)
	if err != nil {
		return err
	}
	if nBytes != 512 {
		return errors.New("ReadAt failed to read enough bytes")
	}
	nBytes, err = f.ReadAt(nb01Header, patcher_common.QY7nb01Offset)
	if err != nil {
		return err
	}
	if nBytes != 512 {
		return errors.New("ReadAt failed to read enough bytes")
	}

	nkOk00Parse, _, err := patcher_common.ParseNKOKROM(&nb00Header, 512, true)
	if err != nil {
		return err
	}

	nkOk01Parse, _, err := patcher_common.ParseNKOKROM(&nb01Header, 512, true)
	if err != nil {
		return err
	}

	if nkOk00Parse.RomSize < 1 || nkOk00Parse.RomSize > 0xFFFFFFFF {
		return errors.New("Invalid NB00 ROM Size!")
	}

	if nkOk01Parse.RomSize < 1 || nkOk01Parse.RomSize > 0xFFFFFFFF {
		return errors.New("Invalid NB01 ROM Size!")
	}

	// Load everything
	var fullRomSize = int(512 + nkOk00Parse.RomSize)
	fullNB00 := make([]byte, 512+nkOk00Parse.RomSize)
	fullNB01 := make([]byte, 512+nkOk00Parse.RomSize)

	nBytes, err = f.ReadAt(fullNB00, patcher_common.QY7nb00Offset)
	if err != nil {
		return err
	}
	if nBytes != fullRomSize {
		return errors.New("ReadAt failed to read enough bytes")
	}
	nkOk00Parse, _, err = patcher_common.ParseNKOKROM(&fullNB00, int64(nBytes), false)
	if err != nil {
		return err
	}

	nBytes, err = f.ReadAt(fullNB01, patcher_common.QY7nb01Offset)
	if err != nil {
		return err
	}
	if nBytes != fullRomSize {
		return errors.New("ReadAt failed to read enough bytes")
	}
	nkOk01Parse, rom, err := patcher_common.ParseNKOKROM(&fullNB01, int64(nBytes), false)
	if err != nil {
		return err
	}

	log(fmt.Sprintf("NB00"))
	log(fmt.Sprintf("--%s", nkOk00Parse.RomFileName))
	log(fmt.Sprintf("--ROM SIZE %#04x, %d", nkOk00Parse.RomSize, nkOk00Parse.RomSize))
	log(fmt.Sprintf("--VERSION %s", nkOk00Parse.VersionString))
	log(fmt.Sprintf("--SUM2 %#02x", nkOk00Parse.Sum2))
	log(fmt.Sprintf("--SUM4 %#04x\n", nkOk00Parse.Sum4))

	log(fmt.Sprintf("NB01"))
	log(fmt.Sprintf("--%s", nkOk01Parse.RomFileName))
	log(fmt.Sprintf("--ROM SIZE %#04x, %d", nkOk01Parse.RomSize, nkOk01Parse.RomSize))
	log(fmt.Sprintf("--VERSION %s", nkOk01Parse.VersionString))
	log(fmt.Sprintf("--SUM2 %#02x", nkOk01Parse.Sum2))
	log(fmt.Sprintf("--SUM4 %#04x\n", nkOk01Parse.Sum4))

	if nkOk00Parse.RomSize != nkOk01Parse.RomSize {
		return errors.New("Invalid NB00 and NB01 RomSize do not match! Corrupt disk?")
	}

	if nkOk00Parse.Sum2 != nkOk01Parse.Sum2 {
		return errors.New("Invalid NB00 and NB01 SUM2 do not match! Corrupt disk?")
	}

	if nkOk00Parse.Sum4 != nkOk01Parse.Sum4 {
		return errors.New("Invalid NB00 and NB01 SUM2 do not match! Corrupt disk?")
	}

	patchedRom, err := RunPatch_AgreeQY7(&rom)

	if err != nil {
		log("Patch AgreeQY7 failed!")
		return err
	}

	nkOkRepack, err := patcher_common.PackNKOKROM(nkOk00Parse, patchedRom)
	if err != nil {
		return err
	}

	log(fmt.Sprintf("PATCHED ROM"))
	sum4 := patcher_common.CalculateSUM4(&rom, len(rom))
	sum2 := patcher_common.CalculateSUM2(&rom, len(rom))
	log(fmt.Sprintf("--ROM SIZE %#04x %d", len(patchedRom), len(patchedRom)))
	log(fmt.Sprintf("--SUM2 %#02x", sum2))
	log(fmt.Sprintf("--SUM4 %#04x\n", sum4))

	if len(nkOkRepack) != fullRomSize {
		return errors.New("ROM size mismatch! Why has ROM growm in size??")
	}

	log("Writing NB00 back to disk..")

	at, err := f.WriteAt(nkOkRepack, patcher_common.QY7nb00Offset)
	if err != nil {
		return err
	}
	if at != fullRomSize {
		return errors.New("failed to write enough bytes for nb00 offset")
	}
	log("Writing NB01 back to disk..")
	at, err = f.WriteAt(nkOkRepack, patcher_common.QY7nb01Offset)
	if at != fullRomSize {
		return errors.New("failed to write enough bytes for nb01 offset")
	}

	log("Patching complete!")

	return err
}

//go:embed qy7agree.jpeg
var previewImg []byte

var PatchImpl = &patch.Patch{
	PatchName:  "Remove consent screen on QY7XXX (AZE0, E-NV200) NOT FOR JAPAN!",
	PatchImage: &previewImg,
	Patcher:    applyPatch,
	MediaType:  patch.MediaTypeSD,
}
