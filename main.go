package main

import (
	"LeafSDTools_Companion/disk"
	"LeafSDTools_Companion/privilege"
	"LeafSDTools_Companion/utils"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image/color"
	"io"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	filedialog "github.com/sqweek/dialog"
)

var logEntry *widget.Entry

func logAppend(s string) {
	fyne.Do(func() {
		if logEntry == nil {
			return
		}
		current := logEntry.Text
		logEntry.SetText(current + s + "\n")
		logEntry.CursorRow = strings.Count(logEntry.Text, "\n") + 5
		logEntry.Refresh()
	})
}

type greenPrimaryTheme struct{ fyne.Theme }

func (t greenPrimaryTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	if n == theme.ColorNamePrimary {
		return color.NRGBA{R: 0x27, G: 0xae, B: 0x60, A: 0xff}
	}
	return t.Theme.Color(n, v)
}

// fsType is a filesystem recognised in a boot sector: the MBR type byte to
// write when the entry has to be corrected, plus the other bytes that already
// label the same filesystem and must therefore be left alone.
type fsType struct {
	name string
	want byte
	also []byte
}

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
	logAppend("\n────────────────────────────────────────")
	var hold disk.VolumeHold
	if isDevice {
		logAppend(fmt.Sprintf("Target device: %s", path))
		logAppend("Locking/unmounting volumes..")
		var herr error
		hold, herr = disk.HoldDeviceVolumes(path)
		if herr != nil {
			logAppend("Could not reserve device " + herr.Error())
			return
		} else if hold != nil {
			defer hold.Close()
		}
	} else {
		logAppend(fmt.Sprintf("Target image: %s", path))
	}

	rw, size, err := disk.OpenDeviceForReadWrite(path)
	if err != nil {
		logAppend(fmt.Sprintf("Cannot open for read/write: %v", err))
		return
	}
	defer rw.Close()

	type ra interface {
		ReadAt([]byte, int64) (int, error)
		WriteAt([]byte, int64) (int, error)
	}
	f, ok := rw.(ra)
	if !ok {
		logAppend("Opened target does not support random access")
		return
	}

	if size > 0 && size < 1024 {
		logAppend("Target is too small (< 1024 bytes)")
		return
	}
	if size > 0 {
		logAppend(fmt.Sprintf("Size: %s", utils.HumanSize(size)))
	}

	mbr := make([]byte, 512)
	if _, err = f.ReadAt(mbr, 0); err != nil && err != io.EOF {
		logAppend(fmt.Sprintf("Failed to read first 512 bytes: %v", err))
		return
	}
	mbr2 := make([]byte, 512)
	if _, err = f.ReadAt(mbr2, 512); err != nil && err != io.EOF {
		logAppend(fmt.Sprintf("Failed to read second 512 bytes: %v", err))
		return
	}

	if mbr[510] != 0x55 || mbr[511] != 0xAA {
		logAppend("No valid MBR signature (55 AA) at sector 0")
		return
	}
	logAppend("MBR1 signature found")

	if mbr2[510] != 0x55 || mbr2[511] != 0xAA {
		logAppend("No valid MBR signature (55 AA) at sector 1")
		return
	}
	logAppend("MBR2 signature found")

	expected := []byte("CLARION ID")
	if len(mbr2) < 10 || !bytes.Equal(mbr2[0:10], expected) {
		logAppend("ERROR: Clarion signature not found in MBR2, not a valid Leaf/Clarion backup?")
		return
	}
	logAppend("Found Clarion signature, copying MBR2 → MBR1...")

	newMbr1 := make([]byte, 512)
	copy(newMbr1, mbr2)
	copy(newMbr1, make([]byte, 10)) // zero Clarion ID

	logAppend("\nChecking partition types against the filesystems on disk..")
	correctPartitionTypes(newMbr1, f, size, logAppend)

	if _, err = f.WriteAt(newMbr1, 0); err != nil {
		logAppend(fmt.Sprintf("Cannot write MBR: %v", err))
		return
	}

	logAppend("Done. Hidden system partitions should now be visible after re-insert / remount.")
	logAppend("────────────────────────────────────────")
}

func buildFixTab() fyne.CanvasObject {
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
			logAppend("Failed to list devices: " + err.Error())
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
			logAppend("Open dialog error: " + err.Error())
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
				logAppend("Please select a device first.")
				return
			}
			selectedDevice = d
			status.SetText("Device: " + d.String())
			go fixPartitionTable(selectedDevice.Path, true)
			return
		}
		if imagePath == "" {
			logAppend("Please choose an image file first.")
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

// --- Create / Restore image tabs --------------------------------------------

func buildDevicePicker() (*widget.Select, *map[string]disk.Device, func()) {
	deviceByLabel := map[string]disk.Device{}
	sel := widget.NewSelect(nil, nil)
	sel.PlaceHolder = "Select device..."
	refresh := func() {
		list, err := disk.ListDevices()
		if err != nil {
			logAppend("Failed to list devices: " + err.Error())
			return
		}
		deviceByLabel = map[string]disk.Device{}
		opts := make([]string, len(list))
		for i, d := range list {
			opts[i] = d.String()
			deviceByLabel[d.String()] = d
		}
		sel.Options = opts
		sel.ClearSelected()
		sel.Refresh()
	}
	return sel, &deviceByLabel, refresh
}

func buildBackupTab() fyne.CanvasObject {
	deviceSelect, deviceByLabel, refreshDevices := buildDevicePicker()
	refreshBtn := widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), refreshDevices)

	var destPath string
	destLabel := widget.NewLabel("No file chosen")
	destLabel.Wrapping = fyne.TextWrapWord
	chooseDest := widget.NewButton("Save as...", func() {
		filename, err := filedialog.File().Filter("Disk Image", "img").Save()
		if err != nil {
			logAppend("Save dialog error: " + err.Error())
			return
		}
		if filename == "" {
			return
		}
		if !strings.HasSuffix(strings.ToLower(filename), ".img") {
			filename += ".img"
		}
		destPath = filename
		destLabel.SetText(filepath.Base(destPath))
	})

	progress := widget.NewProgressBar()
	status := widget.NewLabel("")
	var cancelChan chan struct{}
	busy := false

	startBtn := widget.NewButton("Start backup", nil)
	cancelBtn := widget.NewButton("Cancel", nil)
	cancelBtn.Disable()
	startBtn.Importance = widget.HighImportance

	startBtn.OnTapped = func() {
		if busy {
			return
		}
		src, ok := (*deviceByLabel)[deviceSelect.Selected]
		if !ok {
			logAppend("Select a source device first.")
			return
		}
		if destPath == "" {
			logAppend("Choose a destination file first.")
			return
		}
		logAppend("\n────────────────────────────────────────")
		logAppend(fmt.Sprintf("Backup %s to %s", src.Path, destPath))
		cancelChan = make(chan struct{})
		busy = true
		startBtn.Disable()
		cancelBtn.Enable()
		progress.SetValue(0)
		status.SetText("Starting...")

		go func() {
			err := disk.CreateDiskImage(src.Path, destPath, 4*1024*1024, func(written, total int64, rate float64) {
				fyne.Do(func() {
					if total > 0 {
						progress.SetValue(float64(written) / float64(total))
						status.SetText(fmt.Sprintf("%s / %s — %s/s", utils.HumanSize(written), utils.HumanSize(total), utils.HumanSize(int64(rate))))
					} else {
						status.SetText(fmt.Sprintf("%s — %s/s", utils.HumanSize(written), utils.HumanSize(int64(rate))))
					}
				})
			}, cancelChan)
			fyne.Do(func() {
				busy = false
				startBtn.Enable()
				cancelBtn.Disable()
				if err != nil {
					logAppend("Backup failed: " + err.Error())
					if errors.Is(err, os.ErrPermission) {
						logAppend("Permission denied, approve the OS prompt and try again.")
					}
				} else {
					progress.SetValue(1)
					logAppend("Backup complete: " + destPath)
				}
				logAppend("────────────────────────────────────────")
			})
		}()
	}
	cancelBtn.OnTapped = func() {
		if cancelChan != nil {
			close(cancelChan)
			cancelChan = nil
		}
	}

	refreshDevices()

	return container.NewVBox(
		widget.NewLabelWithStyle("Backup SD", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		container.NewBorder(nil, nil, nil, refreshBtn, deviceSelect),
		container.NewBorder(nil, nil, nil, chooseDest, destLabel),
		progress,
		status,
		container.NewHBox(startBtn, cancelBtn),
	)
}

func buildRestoreTab() fyne.CanvasObject {
	deviceSelect, deviceByLabel, refreshDevices := buildDevicePicker()
	refreshBtn := widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), refreshDevices)

	var imgPath string
	imgLabel := widget.NewLabel("No image chosen")
	imgLabel.Wrapping = fyne.TextWrapWord
	chooseImg := widget.NewButton("Open image...", func() {
		filename, err := filedialog.File().Filter("Disk Image", "img").Load()
		if err != nil {
			logAppend("Open dialog error: " + err.Error())
			return
		}
		if filename == "" {
			return
		}
		imgPath = filename
		imgLabel.SetText(filepath.Base(imgPath))
	})

	verifyCheck := widget.NewCheck("Verify after write", nil)
	verifyCheck.SetChecked(true)

	progress := widget.NewProgressBar()
	status := widget.NewLabel("")
	var cancelChan chan struct{}
	busy := false

	startBtn := widget.NewButton("Start restore", nil)
	cancelBtn := widget.NewButton("Cancel", nil)
	cancelBtn.Disable()
	startBtn.Importance = widget.DangerImportance

	startBtn.OnTapped = func() {
		if busy {
			return
		}
		dst, ok := (*deviceByLabel)[deviceSelect.Selected]
		if !ok {
			logAppend("Select a destination device first.")
			return
		}
		if imgPath == "" {
			logAppend("Choose an image file first.")
			return
		}
		doVerify := verifyCheck.Checked

		warn := fmt.Sprintf(
			"This will OVERWRITE all data on:\n\n  %s\n  %s\n\nwith the image:\n\n  %s\n\nThis cannot be undone. Continue?",
			dst.Name, dst.Path, filepath.Base(imgPath),
		)
		if !filedialog.Message("%s", warn).Title("Confirm restore").YesNo() {
			return
		}

		logAppend("\n────────────────────────────────────────")
		logAppend(fmt.Sprintf("Restore %s to %s", imgPath, dst.Path))
		logAppend("WARNING: All data on the target device will be overwritten.")
		if doVerify {
			logAppend("Verification after write is enabled.")
		}
		cancelChan = make(chan struct{})
		busy = true
		startBtn.Disable()
		cancelBtn.Enable()
		progress.SetValue(0)
		fyne.CurrentApp().Settings().SetTheme(theme.DefaultTheme())
		status.SetText("Writing...")

		phase := "Writing"
		go func() {
			err := disk.RestoreDiskImage(imgPath, dst.Path, 4*1024*1024, doVerify, func(written, total int64, rate float64) {
				fyne.Do(func() {
					// written == -1 is the "flushing to device" sentinel
					if written == -1 {
						if phase != "Flushing" {
							phase = "Flushing"
							logAppend("Write finished, flushing to device (this can take a while on slow media)...")
						}
						status.SetText(fmt.Sprintf("Flushing to device — %ds", int64(rate)))
						return
					}
					if (phase == "Writing" || phase == "Flushing") && written == 0 && progress.Value > 0.5 {
						phase = "Verifying"
						fyne.CurrentApp().Settings().SetTheme(greenPrimaryTheme{Theme: theme.DefaultTheme()})
						logAppend("Writing done, verifying...")
					}
					label := phase
					if total > 0 {
						progress.SetValue(float64(written) / float64(total))
						status.SetText(fmt.Sprintf("%s: %s / %s — %s/s", label, utils.HumanSize(written), utils.HumanSize(total), utils.HumanSize(int64(rate))))
					} else {
						status.SetText(fmt.Sprintf("%s: %s — %s/s", label, utils.HumanSize(written), utils.HumanSize(int64(rate))))
					}
				})
			}, cancelChan)
			fyne.Do(func() {
				busy = false
				startBtn.Enable()
				cancelBtn.Disable()
				fyne.CurrentApp().Settings().SetTheme(theme.DefaultTheme())
				if err != nil {
					logAppend("Restore failed: " + err.Error())
					if errors.Is(err, os.ErrPermission) {
						logAppend("Permission denied, approve the OS prompt and try again.")
					}
				} else {
					progress.SetValue(1)
					if doVerify {
						logAppend("Restore complete, verification passed.")
					} else {
						logAppend("Restore complete.")
					}
				}
				logAppend("────────────────────────────────────────")
			})
		}()
	}
	cancelBtn.OnTapped = func() {
		if cancelChan != nil {
			close(cancelChan)
			cancelChan = nil
		}
	}

	refreshDevices()

	return container.NewVBox(
		widget.NewLabelWithStyle("Restore backup to SD", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		container.NewBorder(nil, nil, nil, chooseImg, imgLabel),
		container.NewBorder(nil, nil, nil, refreshBtn, deviceSelect),
		verifyCheck,
		progress,
		status,
		container.NewHBox(startBtn, cancelBtn),
	)
}

func main() {
	if privilege.RunHelperIfRequested() {
		return
	}

	a := app.NewWithID("lst_comp")
	w := a.NewWindow("Leaf SD Tools Companion")

	logEntry = widget.NewMultiLineEntry()
	logEntry.Wrapping = fyne.TextWrapWord
	logEntry.TextStyle = fyne.TextStyle{Monospace: true}
	logEntry.SetMinRowsVisible(6)

	tabs := container.NewAppTabs(
		container.NewTabItem("Fix partitions", buildFixTab()),
		container.NewTabItem("Backup", buildBackupTab()),
		container.NewTabItem("Restore", buildRestoreTab()),
		container.NewTabItem("Patches", container.NewVBox(
			widget.NewLabelWithStyle("Patches", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			widget.NewLabel("TODO — not ready yet"),
		)),
	)

	mainContent := container.NewBorder(tabs, nil, nil, nil, logEntry)
	w.SetContent(container.NewPadded(mainContent))
	w.Resize(fyne.NewSize(820, 520))

	logAppend("Leaf SD Tools Companion v1.0.5")
	logAppend("https://github.com/developerfromjokela/leafsdtools_companion")
	logAppend("NOTE — always keep a backup of the original SD card.")

	w.ShowAndRun()
}
