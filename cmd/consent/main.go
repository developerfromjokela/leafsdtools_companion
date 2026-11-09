// consent skips the telematics consent screen in a QY8 navigation image,
// either on a card image file or on a saved .mod container.
//
// Usage: consent [-apply] <card.img|nav.mod>
//
// Without -apply nothing is written: the plan is checked and reported.
package main

import (
	"flag"
	"fmt"
	"os"

	"LeafSDTools_Companion/patch/qy8consent"
)

func main() {
	apply := flag.Bool("apply", false, "write the patched image back to the file")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: consent [-apply] <card.img|nav.mod>")
		os.Exit(2)
	}
	path := flag.Arg(0)

	st, err := os.Stat(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	log := func(s string) { fmt.Println(s) }

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()

	res, writes, err := qy8consent.Plan(f, st.Size(), log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		os.Exit(1)
	}
	fmt.Printf("plan: %s at 0x%x, chunk %d (%d -> %d bytes, room %d), %d pages, drift 0x%08x\n",
		res.Target.Build, res.Target.Offset, res.Chunk, res.Stock, res.Packed, res.Room, res.Pages, res.Compensation)
	for i, w := range writes {
		if i < 8 {
			fmt.Printf("  page 0x%010x (%d bytes)\n", w.Offset, len(w.Data))
		}
	}
	if len(writes) > 8 {
		fmt.Printf("  ... %d more\n", len(writes)-8)
	}
	fmt.Println("sha256 of the patched image:", res.SHA256)
	if !*apply {
		fmt.Println("not applied; re-run with -apply")
		return
	}
	if err := qy8consent.PatchImpl.ApplyPatch(f, st.Size(), log); err != nil {
		fmt.Fprintln(os.Stderr, "apply:", err)
		os.Exit(1)
	}
	fmt.Println("applied")
}
