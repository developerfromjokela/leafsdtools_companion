package ui

import (
	"LeafSDTools_Companion/disk"
	"LeafSDTools_Companion/patch"
	"fmt"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	filedialog "github.com/sqweek/dialog"
)

// applyPatch runs chosen patch
func applyPatch(path string, isDevice bool, chosenPatch *patch.Patch) {
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
	closed := false
	defer func() {
		if !closed {
			_ = rw.Close()
		}
	}()

	f, ok := rw.(patch.ReadWriterAt)
	if !ok {
		LogAppend("Opened target does not support random access")
		return
	}

	err = chosenPatch.ApplyPatch(f, size, LogAppend)
	if err != nil {
		LogAppend(fmt.Sprintf("Patch not applied: %v", err))
		LogAppend("────────────────────────────────────────")
		return
	}
	if err := rw.Close(); err != nil {
		closed = true
		LogAppend(fmt.Sprintf("Patch not applied: closing target: %v", err))
		LogAppend("────────────────────────────────────────")
		return
	}
	closed = true
	LogAppend("────────────────────────────────────────")
}

func BuildPatchTab(window *fyne.Window) fyne.CanvasObject {
	status := widget.NewLabel("Choose a target, then apply the patch.")
	status.Wrapping = fyne.TextWrapWord

	var imagePath string
	var selectedDevice disk.Device
	var selectedPatch *patch.Patch
	var modeRadio *widget.RadioGroup
	var refreshBtn *widget.Button
	var chooseImageBtn *widget.Button
	deviceByLabel := map[string]disk.Device{}

	patches := AllPatches()
	patchByName := map[string]*patch.Patch{}
	patchNames := make([]string, len(patches))
	for i, p := range patches {
		patchNames[i] = p.PatchName
		patchByName[p.PatchName] = p
	}

	patchImage := canvas.NewImageFromResource(nil)
	patchImage.FillMode = canvas.ImageFillContain
	patchImage.SetMinSize(fyne.NewSize(160, 120))
	patchImage.Hide()

	patchNameLabel := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})
	patchNameLabel.Hide()

	deviceSelect := widget.NewSelect(nil, nil)

	patchSelect := widget.NewSelect(patchNames, func(name string) {
		p, ok := patchByName[name]
		if !ok {
			selectedPatch = nil
			patchImage.Hide()
			patchNameLabel.Hide()
			return
		}
		selectedPatch = p
		if p.PatchImage != nil {
			patchImage.Resource = fyne.NewStaticResource(p.PatchName+".jpg", *p.PatchImage)
			patchImage.Refresh()
			patchImage.Show()
		} else {
			patchImage.Hide()
		}
		patchNameLabel.SetText(p.PatchName)
		patchNameLabel.Show()
		if p.MediaType == patch.MediaTypeSD {
			modeRadio.Show()
			chooseImageBtn.SetText("Choose .img file...")
		} else if p.MediaType == patch.MediaTypeNAND {
			refreshBtn.Hide()
			modeRadio.SetSelected("Disk image (.img)")
			modeRadio.Hide()
			chooseImageBtn.SetText("Choose nand_xx.bin..")
		}
	})
	patchSelect.PlaceHolder = "Select patch..."

	imageLabel := widget.NewLabel("No image selected")
	imageLabel.Wrapping = fyne.TextWrapWord

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

	chooseImageBtn = widget.NewButton("Choose .img file...", func() {
		var mediaTypeDesc = "DiskImage"
		var mediaTypeExtension = "DiskImage"
		if selectedPatch.MediaType == patch.MediaTypeNAND {
			mediaTypeDesc = "NAND Dump (nand_xx.bin)"
			mediaTypeExtension = ".bin"
		}
		filename, err := filedialog.File().Filter(mediaTypeDesc, mediaTypeExtension).Load()
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

	refreshBtn = widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), refreshDevices)
	refreshBtn.Hide()

	deviceRow := container.NewBorder(nil, nil, nil, refreshBtn, deviceSelect)
	deviceRow.Hide()

	modeRadio = widget.NewRadioGroup([]string{"Disk image (.img)", "Physical device"}, func(s string) {
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

	applyBtn := widget.NewButton("Apply patch", func() {
		if selectedPatch == nil {
			LogAppend("Please select a patch first.")
			return
		}

		var target string
		var isDevice bool
		var statusText string

		if modeRadio.Selected == "Physical device" {
			d, ok := deviceByLabel[deviceSelect.Selected]
			if !ok {
				LogAppend("Please select a device first.")
				return
			}
			selectedDevice = d
			target = selectedDevice.Path
			isDevice = true
			statusText = "Device: " + d.String()
		} else {
			if imagePath == "" {
				LogAppend("Please choose a file first.")
				return
			}
			target = imagePath
			statusText = "File: " + filepath.Base(imagePath)
		}

		msg := widget.NewLabel(
			"Patching modifies the original data and cannot be undone.\n\n" +
				"Before continuing, make sure you have a full backup of your original SD card or NAND.\n\nFor SD, use Backup tab. For NAND, make a duplicate file of nand_xx.bin as a backup.")
		msg.Wrapping = fyne.TextWrapWord

		d := dialog.NewCustomConfirm(
			"Backup required",
			"I have a backup, continue",
			"Cancel",
			msg,
			func(confirmed bool) {
				if !confirmed {
					return
				}
				status.SetText(statusText)
				go applyPatch(target, isDevice, selectedPatch)
			},
			*window,
		)
		d.Resize(fyne.NewSize(460, 220))
		d.Show()
	})
	applyBtn.Importance = widget.HighImportance

	return container.NewVBox(
		widget.NewLabelWithStyle("Patches", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		modeRadio,
		chooseImageBtn,
		imageLabel,
		deviceRow,
		widget.NewSeparator(),
		patchSelect,
		container.NewCenter(patchImage),
		patchNameLabel,
		layout.NewSpacer(),
		status,
		applyBtn,
	)
}
