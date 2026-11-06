package btdun_qy7

import (
	patchercommon "LeafSDTools_Companion/patch/common"
	"LeafSDTools_Companion/patch/wince"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// dccMtx0300FuncLogName Find (WCHAR)dcc_mtx_03_00 in .text section, used in NKDbgPrintfW
var dccMtx0300FuncLogName = []byte{
	0x64, 0x00, 0x63, 0x00, 0x63, 0x00, 0x5f, 0x00, 0x6d, 0x00,
	0x74, 0x00, 0x78, 0x00, 0x5f, 0x00, 0x30, 0x00, 0x33, 0x00,
	0x5f, 0x00, 0x30, 0x00, 0x30, 0x00, 0x00,
}

// dccMtx0300FuncLogName Find (WCHAR)dcc_mtx_03_00 in .text section, used in NKDbgPrintfW
var dccMtx0302FuncLogName = []byte{
	0x64, 0x00, 0x63, 0x00, 0x63, 0x00, 0x5f, 0x00, 0x6d, 0x00,
	0x74, 0x00, 0x78, 0x00, 0x5f, 0x00, 0x30, 0x00, 0x33, 0x00,
	0x5f, 0x00, 0x30, 0x00, 0x32, 0x00, 0x00,
}

var dccGetThreadObjFuncLogName = []byte{
	0x5B, 0x00, 0x44, 0x00, 0x43, 0x00, 0x43, 0x00, 0x5D, 0x00,
	0x20, 0x00, 0x64, 0x00, 0x63, 0x00, 0x63, 0x00, 0x5F, 0x00,
	0x47, 0x00, 0x65, 0x00, 0x74, 0x00, 0x54, 0x00, 0x68, 0x00,
	0x72, 0x00, 0x65, 0x00, 0x61, 0x00, 0x64, 0x00, 0x4F, 0x00,
	0x62, 0x00, 0x6A, 0x00, 0x20, 0x00, 0x2D, 0x00, 0x20, 0x00,
}

var dccCallback2successFuncLogName = []byte{
	0x64, 0x00, 0x63, 0x00, 0x63, 0x00, 0x5f, 0x00, 0x43, 0x00,
	0x61, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x62, 0x00, 0x61, 0x00,
	0x63, 0x00, 0x6b, 0x00, 0x32, 0x00, 0x53, 0x00, 0x75, 0x00,
	0x63, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00,
}

// dccCallback2SuccessPatch Calls dcc_GetThreadObj, sends IPC message using WriteIPCMessageQueueToThread, then nop sled to end.
var dccCallback2SuccessPatch = []byte{
	0x43, 0x68, 0x53, 0x69, 0x17, 0xd0, 0x0b, 0x40, 0x09, 0x00,
	0x03, 0x64, 0x16, 0xd5, 0x82, 0x68, 0x09, 0x00, 0x02, 0xe6,
	0x83, 0x67, 0x16, 0xd0, 0x0b, 0x40, 0x09, 0x00, 0x09, 0x00,
	0x09, 0x00, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00,
	0x09, 0x00, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00,
	0x09, 0x00, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00,
	0x09, 0x00, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00,
	0x09, 0x00, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00,
	0x09, 0x00, 0x09, 0x00, 0x09, 0x00,
}

var writeIPCMessageQueueToThreadSignature = []byte{
	0x86, 0x2f, 0x22, 0x4f, 0xd0, 0x7f, 0x14, 0xe8, 0x43, 0x54,
	0xfc, 0x38, 0x00, 0xe3, 0x83, 0x62, 0x04, 0x72, 0x35, 0x1f,
	0x32, 0x22, 0x48, 0x24, 0x31, 0x12, 0x32, 0x12, 0x33, 0x12,
	0x34, 0x12, 0x02, 0x8f, 0x35, 0x12, 0x0b, 0xa0, 0x00, 0xe2,
}

func FindAddress(machineCode []byte, searchData []byte, realAddr uint32) (uint32, uint32, error) {
	for from := 0; from < len(machineCode); {
		i := bytes.Index(machineCode[from:], searchData)
		if i < 0 {
			break
		}
		return realAddr + uint32(from+i), uint32(from + i), nil
	}

	return 0, 0, errors.New("could not find searchData")
}

// FindFunctionByLogString Locates log string, uses its address to find its address below the function.
// negativeOffset is subtracted to get actual function "head" address.
func FindFunctionByLogString(machineCode []byte, logString []byte, realAddr uint32, negativeOffset uint32) (uint32, uint32, error) {
	logAddr, _, err := FindAddress(machineCode, logString, realAddr)
	if err != nil {
		return 0, 0, fmt.Errorf("FindAddress logString: %v", err)
	}

	logAddrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(logAddrBytes, logAddr)

	funcTailAddr, funcTailoffset, err := FindAddress(machineCode, logAddrBytes, realAddr)
	if err != nil {
		return 0, 0, fmt.Errorf("FindAddress logAddrBytes: %v", err)
	}

	return funcTailAddr - negativeOffset, funcTailoffset - negativeOffset, nil
}

var TelemaBTDUNPatches = []patchercommon.FuncPatch{
	{
		Name:   "BTDUN_Flag1",
		SigHex: "f6 68 0b 00 23 60 0b d3 0b 43 09 00 0c 63 38 23 f0 8b 09 d3 0b 43 ?? e4 ed af 00 e2",
		Patches: []patchercommon.BytePatch{
			{RelOffset: 0x16, Old: []byte{0x01}, New: []byte{0x00}},
		},
	},
	{
		Name: "BTDUN_Flag2",
		SigHex: "0b 43 b3 18 82 63 32 29 1f d3 0b 43 09 00 08 20 1d 8d 03 64 82 67 1d d5 1d d3 0b 43 " +
			"?? e6 08 20 05 8b 1c d3 0b 43 83 64 1b d8 03 a0 09 00 0f a0",
		Patches: []patchercommon.BytePatch{
			{RelOffset: 0x1c, Old: []byte{0x02}, New: []byte{0x00}},
		},
	},
	{
		Name: "BTDUN_Flag3",
		SigHex: "1f d3 93 65 0b 43 83 64 1e d3 93 65 0b 43 83 64 28 a0 09 00 1e d3 0b 43 09 00 " +
			"?? 88 1c 8b 1d d3 0b 43 09 00 0c 63 38 23 16 8b 1b d3 0b 43 82 64",
		Patches:  []patchercommon.BytePatch{{RelOffset: 0x1a, Old: []byte{0x01}, New: []byte{0x00}}},
		MaxCount: 2,
	},
	{
		Name: "BTDUN_Flag4",
		SigHex: "1e d3 93 65 0b 43 83 64 28 a0 09 00 1e d3 0b 43 09 00 " +
			"?? 88 1c 8b 1d d3 0b 43 09 00 0c 63 38 23 16 8b 1b d3 0b 43 82 64 1a d3 0b 43 09 00 0c 63",
		Patches:  []patchercommon.BytePatch{{RelOffset: 0x12, Old: []byte{0x01}, New: []byte{0x00}}},
		MaxCount: 2,
	},
}

func RunPatch_BTDUNQY7(nbKernel *[]byte) ([]byte, *[]patchercommon.PatchResult, error) {
	var ex *wince.Extractor
	ex, err := wince.NewExtractor(*nbKernel)
	if err != nil {
		return nil, nil, err
	}

	var module *wince.Module = nil

	for _, m := range ex.Modules {
		if m.Name == "Telema.exe" {
			module = m
			break
		}
	}

	if module == nil {
		return nil, nil, errors.New("cannot find Telema.exe")
	}

	res, err := patchercommon.ApplyFuncPatches(module, ".text", TelemaBTDUNPatches)
	if err != nil {
		return nil, nil, err
	}

	sections, err := module.Sections()
	if err != nil {
		return nil, nil, err
	}
	var textSection *wince.Section = nil
	for _, section := range sections {
		if section.Name == ".text" {
			textSection = &section
		}
	}

	if textSection == nil {
		return nil, nil, errors.New("cannot find .text section")
	}

	var textSectionPatched = make([]byte, len((*textSection).Data))
	copy(textSectionPatched, (*textSection).Data)
	leAddrBuffer := make([]byte, 4)

	mtx0302Addr, _, err := FindFunctionByLogString(
		textSectionPatched, dccMtx0302FuncLogName,
		textSection.RealAddr, 0xB4,
	)
	if err != nil {
		return nil, nil, err
	}

	dccMtx0300Addr, _, err := FindFunctionByLogString(
		textSectionPatched, dccMtx0300FuncLogName,
		textSection.RealAddr, 0x78,
	)
	if err != nil {
		return nil, nil, err
	}

	binary.LittleEndian.PutUint32(leAddrBuffer, dccMtx0300Addr)

	_, mtxTableItemOffset, err := FindAddress(textSectionPatched, leAddrBuffer, 0)
	if int(mtxTableItemOffset) > len(textSectionPatched) {
		return nil, nil, errors.New("mtxTableItemOffset out of range")
	}

	binary.LittleEndian.PutUint32(leAddrBuffer, mtx0302Addr)
	// patch dcc_mtx_03_00 call to call dcc_mtx_03_02
	copy(textSectionPatched[mtxTableItemOffset:], leAddrBuffer)

	// Patching callback2Success to fire IPC message to open DUN connection
	_, cb2SuccessOffset, err := FindFunctionByLogString(
		textSectionPatched,
		dccCallback2successFuncLogName,
		textSection.RealAddr, 0x78,
	)
	if err != nil {
		return nil, nil, err
	}

	if textSectionPatched[cb2SuccessOffset] != 0x86 &&
		textSectionPatched[cb2SuccessOffset+1] != 0x2f {
		return nil, nil, fmt.Errorf("unexpected head bytes in cb2Success: %#04x",
			textSectionPatched[cb2SuccessOffset:cb2SuccessOffset+2])
	}

	// Patching callback2Success to fire IPC message to open DUN connection
	dccGetThreadObjAddr, dccGetThreadObjOffset, err := FindFunctionByLogString(
		textSectionPatched,
		dccGetThreadObjFuncLogName,
		textSection.RealAddr, 0x40,
	)
	if err != nil {
		return nil, nil, err
	}

	if textSectionPatched[dccGetThreadObjOffset] != 0x86 &&
		textSectionPatched[dccGetThreadObjOffset+1] != 0x2f {
		return nil, nil, fmt.Errorf("unexpected head bytes in dccGetThreadObj: %#04x",
			textSectionPatched[dccGetThreadObjOffset:dccGetThreadObjOffset+2])
	}

	// Patching callback2Success to fire IPC message to open DUN connection
	writeIPCThreadQFuncAddr, _, err := FindAddress(
		textSectionPatched,
		writeIPCMessageQueueToThreadSignature,
		textSection.RealAddr,
	)
	if err != nil {
		return nil, nil, err
	}

	// machine code patch
	copy(textSectionPatched[cb2SuccessOffset+12:], dccCallback2SuccessPatch)

	// ptr to dcc_GetThreadObj
	binary.LittleEndian.PutUint32(leAddrBuffer, dccGetThreadObjAddr)
	copy(textSectionPatched[cb2SuccessOffset+0x70:], leAddrBuffer)
	// IPC Message destination
	binary.LittleEndian.PutUint32(leAddrBuffer, 0x8000)
	copy(textSectionPatched[cb2SuccessOffset+0x74:], leAddrBuffer)
	// ptr to WriteIPCMessageQueueToThread
	binary.LittleEndian.PutUint32(leAddrBuffer, writeIPCThreadQFuncAddr)
	copy(textSectionPatched[cb2SuccessOffset+0x7C:], leAddrBuffer)

	// Pack .text back to ROM
	err = module.ReplaceSectionByName(".text", textSectionPatched)
	if err != nil {
		return nil, nil, err
	}

	return ex.Bytes(), &res, nil
}
