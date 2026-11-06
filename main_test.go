package main

import (
	"LeafSDTools_Companion/disk"
	"LeafSDTools_Companion/patch"
	"LeafSDTools_Companion/patch/agree_qy7"
	"LeafSDTools_Companion/patch/btdun_qy7"
	patcher_common "LeafSDTools_Companion/patch/common"
	"LeafSDTools_Companion/patch/gpstimefix_qy7"
	"LeafSDTools_Companion/patch/wince"
	"fmt"
	"os"
	"testing"
)

func TestWinCEKernelUtility(t *testing.T) {
	imageFile := ""

	offsetGiven := false

	if st, err := os.Stat(imageFile); err != nil || !st.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "Cannot find file: %s\n", imageFile)
		os.Exit(1)
	}

	image, err := os.ReadFile(imageFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read %s: %v\n", imageFile, err)
		os.Exit(1)
	}

	var ex *wince.Extractor
	if offsetGiven {
		ex, err = wince.NewExtractorAt(image, 0)
	} else {
		ex, err = wince.NewExtractor(image)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to analyze %s: %v\n", imageFile, err)
		os.Exit(1)
	}

	fmt.Println("FILES")
	for _, f := range ex.Files {
		fmt.Println(f.Name)
		fmt.Println("  ", f.Entry.FileAttributes)
		fmt.Printf("   %+v\n", f.Entry.FileTime.Unix())
		fmt.Println("  ", f.Entry.RealFileSize)
		fmt.Println("  ", f.Entry.CompFileSize)
		fmt.Println("  ", f.Entry.FileNamePtr)
		fmt.Println("  ", f.Entry.LoadOffset)
	}
	fmt.Println("Modules")
	for _, m := range ex.Modules {
		fmt.Println(m.Name)
		fmt.Println("  ", m.Toc.FileAttributes)
		fmt.Printf("   %+v\n", m.Toc.FileTime.Unix())
		fmt.Println("  ", m.Toc.FileSize)
	}
}

func TestWinCEKernelUtilityPatching(t *testing.T) {
	imageFile := "../Documents/EliminateOk/NB01.nb0"

	if st, err := os.Stat(imageFile); err != nil || !st.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "Cannot find file: %s\n", imageFile)
		return
	}

	image, err := os.ReadFile(imageFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read %s: %v\n", imageFile, err)
		return
	}

	var ex *wince.Extractor
	ex, err = wince.NewExtractor(image)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to analyze %s: %v\n", imageFile, err)
		return
	}

	err = ex.SaveImage("./Unmodified.nb0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save ROM: %v\n", err)
		return
	}

	var module, found = ex.Module("ScreenStateCC.dll")

	if !found {
		fmt.Fprintf(os.Stderr, "Cannot find ScreenStateCC.dll\n")
		return
	}

	fmt.Println(module.Toc.FileSize)

	sections, err := module.Sections()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get sections: %v\n", err)
		return
	}

	var textSection *wince.Section = nil

	for _, section := range sections {
		if section.Name == ".text" {
			textSection = &section
		}
	}

	if textSection == nil {
		fmt.Fprintf(os.Stderr, "Cannot find .text section\n")
		return
	}

	// Simple test, replace same data and compare
	err = module.ReplaceSectionByName(".text", textSection.Data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to patch section: %v\n", err)
		return
	}

	err = ex.SaveImage("./PatchedNB.nb0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save ROM: %v\n", err)
		return
	}
}

func TestAgreeQY7Patch(t *testing.T) {
	imageFile := "../Documents/EliminateOk/NB01.nb0"

	if st, err := os.Stat(imageFile); err != nil || !st.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "Cannot find file: %s\n", imageFile)
		return
	}

	image, err := os.ReadFile(imageFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read %s: %v\n", imageFile, err)
		return
	}

	patchedImage, patchErr := agree_qy7.RunPatch_AgreeQY7(&image)
	if patchErr != nil {
		fmt.Fprintf(os.Stderr, "Failed to patch AgreeQY7: %v\n", patchErr)
		panic(patchErr)
	}

	fmt.Println(len(patchedImage))
	err = os.WriteFile("./PatchedNB01.nb0", patchedImage, 0644)
	if err != nil {
		return
	}
}

func TestNKOKHeaderInsideDiskIMG(t *testing.T) {
	imageFile := "LEAF_2014_QSD-357-101.img"

	rw, size, err := disk.OpenDeviceForReadWrite(imageFile)
	if err != nil {
		fmt.Println(fmt.Sprintf("Cannot open for read/write: %v", err))
		return
	}
	closed := false
	defer func() {
		if !closed {
			_ = rw.Close()
		}
	}()

	f, ok := rw.(patch.ReadWriterAt)
	if !ok {
		fmt.Println("Opened target does not support random access")
		return
	}

	err = agree_qy7.PatchImpl.ApplyPatch(f, size, nil)
	if err != nil {
		fmt.Println(err)
	}
}

func TestPatcherInsertFile(t *testing.T) {
	imageFile := "../Documents/benchleaf_nand/NB04.nb0tsst"

	if st, err := os.Stat(imageFile); err != nil || !st.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "Cannot find file: %s\n", imageFile)
		return
	}

	image, err := os.ReadFile(imageFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read %s: %v\n", imageFile, err)
		return
	}

	p, err := wince.NewExtractor(image)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to analyze %s: %v\n", imageFile, err)
		return
	}

	image, err = os.ReadFile("go.mod")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read %s: %v\n", imageFile, err)
		return
	}

	f, err := p.AddFile("COREXLL.DLL", image, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to add file: %v\n", err)
		return
	}
	fmt.Printf("Adding file: %s\n", f.Name)
	fmt.Printf("           : %v\n", f)
	p.SaveImage("./NewADDEDFILE.nb0")
}

func TestPatcherCustomECECHeader(t *testing.T) {
	imageFile := "../Documents/benchleaf_nand/NB04.nb0"

	if st, err := os.Stat(imageFile); err != nil || !st.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "Cannot find file: %s\n", imageFile)
		return
	}

	image, err := os.ReadFile(imageFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read %s: %v\n", imageFile, err)
		return
	}

	ecechdr, _, err := patcher_common.ParseCustomECECHDR(&image, int64(len(image)), false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse %s: %v\n", imageFile, err)
		return
	}

	fmt.Printf("Parsed ECEC HDR %v\n", ecechdr)

}

func TestCEDecompress(t *testing.T) {
	imageFile := "../Documents/benchleaf_nand/NB04.nb0"

	if st, err := os.Stat(imageFile); err != nil || !st.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "Cannot find file: %s\n", imageFile)
		return
	}

	image, err := os.ReadFile(imageFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read %s: %v\n", imageFile, err)
		return
	}

	_, rom, err := patcher_common.ParseCustomECECHDR(&image, int64(len(image)), false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse %s: %v\n", imageFile, err)
		return
	}
	p, err := wince.NewExtractor(rom)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to analyze %s: %v\n", imageFile, err)
		return
	}
	fmt.Println("FILES")

	for _, f := range p.Files {
		fmt.Println(f.Name)
		fmt.Println("  ", f.Entry.FileAttributes)
		fmt.Printf("   %+v\n", f.Entry.FileTime.Unix())
		fmt.Println("  ", f.Entry.RealFileSize)
		fmt.Println("  ", f.Entry.CompFileSize)
		fmt.Println("  ", f.Entry.FileNamePtr)
		fmt.Println("  ", f.Entry.LoadOffset)
		if f.Name == "default.hv" {
			dat, err := f.Data()
			if err != nil {
				fmt.Println(err)
				return
			}
			os.WriteFile("default.hv", dat, 0644)
		}
	}

}

func TestGPSTimeFix(t *testing.T) {
	imageFile := "../Documents/benchleaf_nand/NB04.nb0"

	if st, err := os.Stat(imageFile); err != nil || !st.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "Cannot find file: %s\n", imageFile)
		return
	}

	image, err := os.ReadFile(imageFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read %s: %v\n", imageFile, err)
		return
	}

	ecechdr, rom, err := patcher_common.ParseCustomECECHDR(&image, int64(len(image)), false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse %s: %v\n", imageFile, err)
		return
	}

	fmt.Printf("Parsed ECEC HDR %v\n", ecechdr)
	newRom, patchResult, fileResult, err := gpstimefix_qy7.RunPatch_GPSTimeFixQY7(&rom)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to patch GPSTimeFixQY7: %v\n", err)
		return
	}

	fmt.Printf("New ROM LEN %d\n", len(newRom))
	fmt.Printf("New file %v\n", fileResult)
	fmt.Printf("PatchResult %v\n", fileResult)
	fmt.Printf("  PatchAlreadyExisted %v\n", patchResult.AlreadyPatched)
	fmt.Printf("  PatchApplied %v\n", patchResult.Applied)
	fmt.Printf("  Section %v\n", patchResult.Section)
	fmt.Printf("  VirtualAddress %v\n", patchResult.VA)

	_, _, err = patcher_common.FixCustomECECChecksums(newRom)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to fix checksums: %v\n", err)
		return
	}

	err = os.WriteFile("gpstimefix.nb00", newRom, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save GPSTimeFixQY7: %v\n", err)
		return
	}
}

func TestDUNPatcher(t *testing.T) {
	imageFile := "../Documents/EliminateOk/myhu/NB01.nb0"

	if st, err := os.Stat(imageFile); err != nil || !st.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "Cannot find file: %s\n", imageFile)
		return
	}

	image, err := os.ReadFile(imageFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read %s: %v\n", imageFile, err)
		return
	}

	_, patchResults, patchErr := btdun_qy7.RunPatch_BTDUNQY7(&image)
	if patchErr != nil {
		fmt.Fprintf(os.Stderr, "Failed to patch DUN: %v\n", patchErr)
		panic(patchErr)
	}
	for i, patchResult := range *patchResults {
		if patchResult.AlreadyPatched {
			fmt.Printf("FuncPatch(%d) WARN: Function already patched! Skipped..\n", i)
		}
		fmt.Printf("FuncPatch(%d) in %s %v at VA %d (%#08x)\n", i, patchResult.Section, patchResult.Applied, patchResult.VA, patchResult.VA)
	}
}
