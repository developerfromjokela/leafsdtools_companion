package gpstimefix_qy7

import (
	patchercommon "LeafSDTools_Companion/patch/common"
	"LeafSDTools_Companion/patch/wince"
	"bytes"
	_ "embed"
	"errors"
)

// Compiled DLL Shim sitting between navdrv COREDLL calls, intercept GPS buffer and increment Date&Time
// Credit to YDean from 4pda forum!
//
//go:embed COREXLL.dll
var corexllDll []byte

// SetTimeInformationPatch This patch makes navdrv supply raw GPS sensor data to shim
var SetTimeInformationPatch = patchercommon.FuncPatch{
	Name: "SetTimeInformation",
	SigHex: "86 2f 22 4f e0 7f 5c 62 4c 32 21 84 0c 63 40 e0 39 20 40 88 06 8b 02 e1 33 60 19 20 02 88 01 8b 44 a0 00 e2 " +
		"?? ?? 10 73 30 63 50 e1 3c 63 36 31 03 89 63 e1 16 33 3e 91 00 8b 3d 91 1c 33 33 60 23 63 11 73 30 63 10 e8 f8 81 fc 38 3c 63 83 64 33 60 23 63 12 73 f9 81 30 63 3c 63 33 60 23 63 13 73 30 63 fb 81 3c 63 33 60 23 63 14 73 fc 81 15 72 30 63 3c 63 33 60 20 63 fd 81 3c 63 33 60 fe 81 00 e0 0d d3 0b 43 ff 81 0d d3 0b 43 " +
		"?? ?? " +
		"fe 85 03 63 3d 63 38 23 07 8b 0a d2 01 e6 0c 93 22 60 3e 04 08 d3 0b 43 03 e5 01 e2 20 7f 26 4f f6 68 0b 00 23 60 6c 07 d0 07 98 09 " +
		"?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
	Patches: []patchercommon.BytePatch{
		{RelOffset: 0x24, Old: []byte{0x23, 0x63}, New: []byte{0x31, 0xa0}},
		{RelOffset: 0x8e, Old: []byte{0x83, 0x64}, New: []byte{0x23, 0x64}},
	},
}

var coreXllDescriptor = []byte("COREXLL.dll")
var coreDllDescriptor = []byte("COREDLL.dll")

func RunPatch_GPSTimeFixQY7(nbKernel *[]byte) ([]byte, *patchercommon.PatchResult, *wince.File, error) {
	var ex *wince.Extractor
	ex, err := wince.NewExtractor(*nbKernel)
	if err != nil {
		return nil, nil, nil, err
	}

	var module *wince.Module = nil
	var coreDllExists = false

	for _, m := range ex.Modules {
		if m.Name == "coredll.dll" {
			coreDllExists = true
		}
		if m.Name == "navdrv.dll" {
			module = m
			break
		}
	}

	if module == nil {
		return nil, nil, nil, errors.New("cannot find navdrv.dll")
	}
	if !coreDllExists {
		return nil, nil, nil, errors.New("coredll module not found")
	}

	idx, found := module.SectionIndex(".text")
	if !found {
		return nil, nil, nil, errors.New(".text section not found")
	}

	results, err := patchercommon.ApplyFuncPatch(module, ".text", SetTimeInformationPatch)
	if err != nil {
		return nil, nil, nil, err
	}

	// Fix Image Import Descriptor
	allSections, err := module.Sections()
	if err != nil {
		return nil, nil, nil, err
	}
	txtData := allSections[idx].Data
	i := bytes.Index(txtData, coreXllDescriptor)
	coreI := bytes.Index(txtData, coreDllDescriptor)
	if i < 0 && coreI > -1 {
		err = patchercommon.ReplaceInPlace(txtData, coreDllDescriptor, coreXllDescriptor)
		if err != nil {
			return nil, nil, nil, err
		}
		err = module.ReplaceSection(idx, txtData)
		if err != nil {
			return nil, nil, nil, err
		}
	} else if i > -1 && coreI > -1 {
		return nil, nil, nil, errors.New("COREDLL and COREXLL Both present? What is going on? Abort patch!")
	}

	f, err := ex.AddFile("COREXLL.dll", corexllDll, true)
	if err != nil {
		return nil, nil, nil, err
	}

	return ex.Bytes(), results, f, nil
}
