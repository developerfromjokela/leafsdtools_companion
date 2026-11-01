package ui

import (
	"LeafSDTools_Companion/disk"
	"LeafSDTools_Companion/utils"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	filedialog "github.com/sqweek/dialog"
)

func BuildRestoreTab() fyne.CanvasObject {
	deviceSelect, deviceByLabel, refreshDevices := buildDevicePicker()
	refreshBtn := widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), refreshDevices)

	var imgPath string
	imgLabel := widget.NewLabel("No image chosen")
	imgLabel.Wrapping = fyne.TextWrapWord
	chooseImg := widget.NewButton("Open image...", func() {
		filename, err := filedialog.File().Filter("Disk Image", "img").Load()
		if err != nil {
			LogAppend("Open dialog error: " + err.Error())
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
			LogAppend("Select a destination device first.")
			return
		}
		if imgPath == "" {
			LogAppend("Choose an image file first.")
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

		LogAppend("\n────────────────────────────────────────")
		LogAppend(fmt.Sprintf("Restore %s to %s", imgPath, dst.Path))
		LogAppend("WARNING: All data on the target device will be overwritten.")
		if doVerify {
			LogAppend("Verification after write is enabled.")
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
							LogAppend("Write finished, flushing to device (this can take a while on slow media)...")
						}
						status.SetText(fmt.Sprintf("Flushing to device — %ds", int64(rate)))
						return
					}
					if (phase == "Writing" || phase == "Flushing") && written == 0 && progress.Value > 0.5 {
						phase = "Verifying"
						fyne.CurrentApp().Settings().SetTheme(greenPrimaryTheme{Theme: theme.DefaultTheme()})
						LogAppend("Writing done, verifying...")
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
					LogAppend("Restore failed: " + err.Error())
					if errors.Is(err, os.ErrPermission) {
						LogAppend("Permission denied, approve the OS prompt and try again.")
					}
				} else {
					progress.SetValue(1)
					if doVerify {
						LogAppend("Restore complete, verification passed.")
					} else {
						LogAppend("Restore complete.")
					}
				}
				LogAppend("────────────────────────────────────────")
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
