// diag inspects a QY8 navigation image for the consent patch's requirements.
//
// Usage: diag <card.img|nav.mod> [-dump DIR] [-names "AGREE,CONSENT,..."]
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"LeafSDTools_Companion/patch/qy8consent"
)

func main() {
	dump := flag.String("dump", "", "directory to write rom.bin / ScreenStateCC.dll into")
	namesFlag := flag.String("names", "AGREE,CONSENT,SKIP,TELEMA,CWS,START_UP,true,false", "substrings to look for in ScreenStateCC.dll")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: diag <card.img|nav.mod> [-dump DIR] [-names LIST]")
		os.Exit(2)
	}

	d, err := qy8consent.Load(flag.Arg(0), os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "note:", err)
	}
	if d == nil {
		os.Exit(1)
	}
	if *dump != "" {
		d.Dump(*dump)
	}
	if d.Scc == nil {
		fmt.Fprintln(os.Stderr, "ScreenStateCC.dll unavailable, stopping")
		return
	}
	d.Sections()
	skip := d.Ranks()
	d.Handler(skip)
	d.FullDerive()
	d.TryPatch()
	d.Words()
	d.Names(strings.Split(*namesFlag, ",")...)
}
