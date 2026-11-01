package ui

import (
	"LeafSDTools_Companion/disk"
	"LeafSDTools_Companion/utils"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	filedialog "github.com/sqweek/dialog"
)

// accepts reports whether b is already a valid label for this filesystem.
// A partition marked 0x0B (FAT32 CHS) or 0x17 (hidden NTFS) is not wrong, only
// spelled differently, so rewriting it would be an unrelated change.
func (t fsType) accepts(b byte) bool {
	return b == t.want || bytes.IndexByte(t.also, b) >= 0
}

// detectFsType identifies the filesystem from a partition's boot sector.
//
// The Clarion table stores the exFAT partition as 0x0C (FAT32 LBA). The head
// unit does not care — it looks at the boot sector — but Windows, macOS and
// Linux all trust the type byte, so a verbatim copy leaves that partition
// visible yet refused by the automounter.
func detectFsType(vbr []byte) (fsType, bool) {
	if len(vbr) < 512 || vbr[510] != 0x55 || vbr[511] != 0xAA {
		return fsType{}, false
	}
	switch {
	case bytes.Equal(vbr[3:11], []byte("EXFAT   ")):
		return fsType{"exFAT", 0x07, []byte{0x17}}, true
	case bytes.Equal(vbr[3:11], []byte("NTFS    ")):
		return fsType{"NTFS", 0x07, []byte{0x17, 0x27}}, true
	case bytes.Equal(vbr[82:87], []byte("FAT32")):
		return fsType{"FAT32", 0x0C, []byte{0x0B, 0x1B, 0x1C}}, true
	case bytes.Equal(vbr[54:59], []byte("FAT16")):
		return fsType{"FAT16", 0x0E, []byte{0x04, 0x06, 0x14, 0x16, 0x1E}}, true
	case bytes.Equal(vbr[54:59], []byte("FAT12")):
		return fsType{"FAT12", 0x01, []byte{0x11}}, true
	}
	return fsType{}, false
}

// correctPartitionTypes rewrites the type byte of every partition entry in mbr
// to match the filesystem actually present at its start sector. Entries whose
// filesystem cannot be identified are left untouched.
func correctPartitionTypes(mbr []byte, f io.ReaderAt, size int64, log func(string)) {
	for i := 0; i < 4; i++ {
		entry := mbr[446+i*16 : 462+i*16]
		typ := entry[4]
		startLBA := binary.LittleEndian.Uint32(entry[8:12])
		numSectors := binary.LittleEndian.Uint32(entry[12:16])

		if typ == 0x00 || startLBA == 0 || numSectors == 0 {
			continue
		}
		offset := int64(startLBA) * 512
		// size <= 0 means the size could not be determined (raw devices on
		// macOS report 0); in that case just try the read.
		if size > 0 && offset+512 > size {
			log(fmt.Sprintf("Partition %d: starts past end of file, keeping type 0x%02X", i+1, typ))
			continue
		}

		vbr := make([]byte, 512)
		if _, err := f.ReadAt(vbr, offset); err != nil && err != io.EOF {
			log(fmt.Sprintf("Partition %d: cannot read boot sector: %v", i+1, err))
			continue
		}

		fs, ok := detectFsType(vbr)
		if !ok {
			log(fmt.Sprintf("Partition %d: unrecognised filesystem, keeping type 0x%02X", i+1, typ))
			continue
		}
		if fs.accepts(typ) {
			log(fmt.Sprintf("Partition %d: %s, type 0x%02X is correct", i+1, fs.name, typ))
			continue
		}

		entry[4] = fs.want
		log(fmt.Sprintf("Partition %d: %s, corrected type 0x%02X -> 0x%02X", i+1, fs.name, typ, fs.want))
	}
}

func fixPartitionTable(path string, isDevice bool) {
	LogAppend("\n────────────────────────────────────────")
	var hold disk.VolumeHold
	if isDevice {
		LogAppend(fmt.Sprintf("Target device: %s", path))
		LogAppend("Locking/unmounting volumes..")
		var herr error
		hold, herr = disk.HoldDeviceVolumes(path)
		if herr != nil {
			LogAppend("Could not reserve device " + herr.Error())
			return
		} else if hold != nil {
			defer hold.Close()
		}
	} else {
		LogAppend(fmt.Sprintf("Target image: %s", path))
	}

	rw, size, err := disk.OpenDeviceForReadWrite(path)
	if err != nil {
		LogAppend(fmt.Sprintf("Cannot open for read/write: %v", err))
		return
	}
	defer rw.Close()

	type ra interface {
		ReadAt([]byte, int64) (int, error)
		WriteAt([]byte, int64) (int, error)
	}
	f, ok := rw.(ra)
	if !ok {
		LogAppend("Opened target does not support random access")
		return
	}

	if size > 0 && size < 1024 {
		LogAppend("Target is too small (< 1024 bytes)")
		return
	}
	if size > 0 {
		LogAppend(fmt.Sprintf("Size: %s", utils.HumanSize(size)))
	}

	mbr := make([]byte, 512)
	if _, err = f.ReadAt(mbr, 0); err != nil && err != io.EOF {
		LogAppend(fmt.Sprintf("Failed to read first 512 bytes: %v", err))
		return
	}
	mbr2 := make([]byte, 512)
	if _, err = f.ReadAt(mbr2, 512); err != nil && err != io.EOF {
		LogAppend(fmt.Sprintf("Failed to read second 512 bytes: %v", err))
		return
	}

	if mbr[510] != 0x55 || mbr[511] != 0xAA {
		LogAppend("No valid MBR signature (55 AA) at sector 0")
		return
	}
	LogAppend("MBR1 signature found")

	if mbr2[510] != 0x55 || mbr2[511] != 0xAA {
		LogAppend("No valid MBR signature (55 AA) at sector 1")
		return
	}
	LogAppend("MBR2 signature found")

	expected := []byte("CLARION ID")
	if len(mbr2) < 10 || !bytes.Equal(mbr2[0:10], expected) {
		LogAppend("ERROR: Clarion signature not found in MBR2, not a valid Leaf/Clarion backup?")
		return
	}
	LogAppend("Found Clarion signature, copying MBR2 → MBR1...")

	newMbr1 := make([]byte, 512)
	copy(newMbr1, mbr2)
	copy(newMbr1, make([]byte, 10)) // zero Clarion ID

	LogAppend("\nChecking partition types against the filesystems on disk..")
	correctPartitionTypes(newMbr1, f, size, LogAppend)

	if _, err = f.WriteAt(newMbr1, 0); err != nil {
		LogAppend(fmt.Sprintf("Cannot write MBR: %v", err))
		return
	}

	LogAppend("Done. Hidden system partitions should now be visible after re-insert / remount.")
	LogAppend("────────────────────────────────────────")
}

func BuildFixTab() fyne.CanvasObject {
	status := widget.NewLabel("Choose a target, then apply the fix.")
	status.Wrapping = fyne.TextWrapWord

	var imagePath string
	var selectedDevice disk.Device
	deviceByLabel := map[string]disk.Device{}

	imageLabel := widget.NewLabel("No image selected")
	imageLabel.Wrapping = fyne.TextWrapWord

	deviceSelect := widget.NewSelect(nil, nil)
	deviceSelect.PlaceHolder = "Select device..."
	deviceSelect.Hide()

	refreshDevices := func() {
		list, err := disk.ListDevices()
		if err != nil {
			LogAppend("Failed to list devices: " + err.Error())
			return
		}
		deviceByLabel = map[string]disk.Device{}
		opts := make([]string, len(list))
		for i, d := range list {
			opts[i] = d.String()
			deviceByLabel[d.String()] = d
		}
		deviceSelect.Options = opts
		deviceSelect.ClearSelected()
		deviceSelect.Refresh()
	}

	chooseImageBtn := widget.NewButton("Choose .img file...", func() {
		filename, err := filedialog.File().Filter("Disk Image", "img").Load()
		if err != nil {
			LogAppend("Open dialog error: " + err.Error())
			return
		}
		if filename == "" {
			return
		}
		imagePath = filename
		imageLabel.SetText(filepath.Base(filename))
	})

	refreshBtn := widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), refreshDevices)
	refreshBtn.Hide()

	deviceRow := container.NewBorder(nil, nil, nil, refreshBtn, deviceSelect)
	deviceRow.Hide()

	modeRadio := widget.NewRadioGroup([]string{"Disk image (.img)", "Physical device"}, func(s string) {
		switch s {
		case "Disk image (.img)":
			chooseImageBtn.Show()
			imageLabel.Show()
			deviceRow.Hide()
			deviceSelect.Hide()
			refreshBtn.Hide()
		case "Physical device":
			chooseImageBtn.Hide()
			imageLabel.Hide()
			deviceRow.Show()
			deviceSelect.Show()
			refreshBtn.Show()
			refreshDevices()
		}
	})
	modeRadio.SetSelected("Disk image (.img)")
	modeRadio.Horizontal = true

	applyBtn := widget.NewButton("Apply fix", func() {
		if modeRadio.Selected == "Physical device" {
			d, ok := deviceByLabel[deviceSelect.Selected]
			if !ok {
				LogAppend("Please select a device first.")
				return
			}
			selectedDevice = d
			status.SetText("Device: " + d.String())
			go fixPartitionTable(selectedDevice.Path, true)
			return
		}
		if imagePath == "" {
			LogAppend("Please choose an image file first.")
			return
		}
		status.SetText("Image: " + filepath.Base(imagePath))
		go fixPartitionTable(imagePath, false)
	})
	applyBtn.Importance = widget.HighImportance

	return container.NewVBox(
		widget.NewLabelWithStyle("Fix partition table", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Makes hidden Clarion/Leaf system partitions visible."),
		widget.NewSeparator(),
		modeRadio,
		chooseImageBtn,
		imageLabel,
		deviceRow,
		layout.NewSpacer(),
		status,
		applyBtn,
	)
}
