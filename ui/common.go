package ui

import (
	"LeafSDTools_Companion/disk"
	"LeafSDTools_Companion/patch"
	"LeafSDTools_Companion/patch/agree_qy7"
	"LeafSDTools_Companion/patch/btdun_qy7"
	"LeafSDTools_Companion/patch/gpstimefix_qy7"
	"LeafSDTools_Companion/patch/qy8consent"
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

var logEntry *widget.Entry

func LogAppend(s string) {
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

func buildDevicePicker() (*widget.Select, *map[string]disk.Device, func()) {
	deviceByLabel := map[string]disk.Device{}
	sel := widget.NewSelect(nil, nil)
	sel.PlaceHolder = "Select device..."
	refresh := func() {
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
		sel.Options = opts
		sel.ClearSelected()
		sel.Refresh()
	}
	return sel, &deviceByLabel, refresh
}

func InitLogEntry() *widget.Entry {
	logEntry = widget.NewMultiLineEntry()
	logEntry.Wrapping = fyne.TextWrapWord
	logEntry.TextStyle = fyne.TextStyle{Monospace: true}
	logEntry.SetMinRowsVisible(15)
	return logEntry
}

// All Patches

func AllPatches() []*patch.Patch {
	return []*patch.Patch{
		qy8consent.PatchImpl,
		agree_qy7.PatchImpl,
		btdun_qy7.PatchImpl,
		gpstimefix_qy7.PatchImpl,
	}
}
