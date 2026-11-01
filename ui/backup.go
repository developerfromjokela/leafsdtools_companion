package ui

import (
	"LeafSDTools_Companion/disk"
	"LeafSDTools_Companion/utils"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	filedialog "github.com/sqweek/dialog"
)

func BuildBackupTab() fyne.CanvasObject {
	deviceSelect, deviceByLabel, refreshDevices := buildDevicePicker()
	refreshBtn := widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), refreshDevices)

	var destPath string
	destLabel := widget.NewLabel("No file chosen")
	destLabel.Wrapping = fyne.TextWrapWord
	chooseDest := widget.NewButton("Save as...", func() {
		filename, err := filedialog.File().Filter("Disk Image", "img").Save()
		if err != nil {
			LogAppend("Save dialog error: " + err.Error())
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
			LogAppend("Select a source device first.")
			return
		}
		if destPath == "" {
			LogAppend("Choose a destination file first.")
			return
		}
		LogAppend("\n────────────────────────────────────────")
		LogAppend(fmt.Sprintf("Backup %s to %s", src.Path, destPath))
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
					LogAppend("Backup failed: " + err.Error())
					if errors.Is(err, os.ErrPermission) {
						LogAppend("Permission denied, approve the OS prompt and try again.")
					}
				} else {
					progress.SetValue(1)
					LogAppend("Backup complete: " + destPath)
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
		widget.NewLabelWithStyle("Backup SD", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		container.NewBorder(nil, nil, nil, refreshBtn, deviceSelect),
		container.NewBorder(nil, nil, nil, chooseDest, destLabel),
		progress,
		status,
		container.NewHBox(startBtn, cancelBtn),
	)
}
