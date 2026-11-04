package main

import (
	"LeafSDTools_Companion/privilege"
	"LeafSDTools_Companion/ui"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
)

func main() {
	if privilege.RunHelperIfRequested() {
		return
	}

	a := app.NewWithID("lst_comp")
	w := a.NewWindow("Leaf SD Tools Companion")

	tabs := container.NewAppTabs(
		container.NewTabItem("Fix partitions", ui.BuildFixTab()),
		container.NewTabItem("Backup", ui.BuildBackupTab()),
		container.NewTabItem("Restore", ui.BuildRestoreTab()),
		container.NewTabItem("Patches", ui.BuildPatchTab(&w)),
	)

	mainContent := container.NewBorder(tabs, nil, nil, nil, ui.InitLogEntry())
	w.SetContent(container.NewPadded(mainContent))
	w.Resize(fyne.NewSize(820, 520))

	ui.LogAppend("Leaf SD Tools Companion v1.2")
	ui.LogAppend("https://github.com/developerfromjokela/leafsdtools_companion")
	ui.LogAppend("NOTE — always keep a backup of the original SD card.")

	w.ShowAndRun()
}
