package gpstimefix_qy7

import (
	"LeafSDTools_Companion/patch"
	"LeafSDTools_Companion/patch/common"
	_ "embed"
	"errors"
	"fmt"
)

const (
	nb04Offset = 0x40000
)

// IMPL BasePatch

func applyPatch(f patch.ReadWriterAt, size int64, log func(string)) error {
	if size > 10*1024*1024 {
		return errors.New("size too big for a NAND dump, are you sure you have chosen correct file?")
	}
	romHeader := make([]byte, 512)
	nBytes, err := f.ReadAt(romHeader, nb04Offset)
	if err != nil {
		return err
	}
	if nBytes != 512 {
		return errors.New("ReadAt failed to read enough bytes")
	}

	customECECHDR, _, err := patcher_common.ParseCustomECECHDR(&romHeader, 512, true)
	if err != nil {
		return err
	}

	if customECECHDR.RomSize < 1 || customECECHDR.RomSize > 0xFFFFFFFF {
		return errors.New("Invalid NB04 ROM Size!")
	}

	// Load everything
	var fullRomSize = int(customECECHDR.RomSize)
	fullROM := make([]byte, fullRomSize)

	nBytes, err = f.ReadAt(fullROM, nb04Offset)
	if err != nil {
		return err
	}
	if nBytes != fullRomSize {
		return errors.New("ReadAt failed to read enough bytes")
	}
	customECECHDR, _, err = patcher_common.ParseCustomECECHDR(&fullROM, int64(nBytes), false)
	if err != nil {
		return err
	}

	log(fmt.Sprintf("\nNB04"))
	log(fmt.Sprintf("--%s", customECECHDR.RomFileName))
	log(fmt.Sprintf("--ROM SIZE %#04x, %d", customECECHDR.RomSize, customECECHDR.RomSize))
	log(fmt.Sprintf("--VERSION %s", customECECHDR.VersionString))
	log(fmt.Sprintf("--VERSION2 %s", customECECHDR.VersionString2))
	log(fmt.Sprintf("--SUM2 %#02x", customECECHDR.Sum2))
	log(fmt.Sprintf("--SUM4 %#04x\n", customECECHDR.Sum4))

	patchedRom, patchResult, fileResult, err := RunPatch_GPSTimeFixQY7(&fullROM)

	if err != nil {
		log("Patch GPSTimeFixQY7 failed!")
		return err
	}

	if patchResult.AlreadyPatched {
		log("WARN: Function already patched! Not writing anything to navdrv.")
	}
	if patchResult.Applied {
		log(fmt.Sprintf("FuncPatch in %s applied at VA %d (%#04x)", patchResult.Section, patchResult.VA, patchResult.VA))
	}

	log(fmt.Sprintf("ADD FILE (NAME=%s, REALSIZE=%d, COMPSIZE=%d)", fileResult.Name, fileResult.Entry.RealFileSize, fileResult.Entry.CompFileSize))

	log(fmt.Sprintf("\nPATCHED ROM"))
	sum4, sum2, err := patcher_common.FixCustomECECChecksums(patchedRom)
	if err != nil {
		return err
	}
	log(fmt.Sprintf("--ROM SIZE %#04x %d", len(patchedRom), len(patchedRom)))
	log(fmt.Sprintf("--SUM2 %#02x", sum2))
	log(fmt.Sprintf("--SUM4 %#04x\n", sum4))

	if len(patchedRom) != fullRomSize {
		return errors.New("ROM size mismatch! Why has ROM growm in size??")
	}

	log("Writing NB04 back to NAND Img..")

	at, err := f.WriteAt(patchedRom, nb04Offset)
	if err != nil {
		return err
	}
	if at != fullRomSize {
		return errors.New("failed to write enough bytes for nb04 offset")
	}

	log("Patching complete!")

	return err
}

//go:embed gpstimefix.jpg
var previewImg []byte

var PatchImpl = &patch.Patch{
	PatchName:  "Fix GPS Time Rollover + charging&climate control timers sync issue",
	PatchImage: &previewImg,
	Patcher:    applyPatch,
	MediaType:  patch.MediaTypeNAND,
}
