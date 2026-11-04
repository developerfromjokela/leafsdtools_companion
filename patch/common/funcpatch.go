package patcher_common

import (
	"LeafSDTools_Companion/patch/wince"
	"fmt"
	"strconv"
	"strings"
)

// funcpath.go Patching something inside a function

type BytePatch struct {
	RelOffset int
	Old       []byte
	New       []byte
}

type FuncPatch struct {
	Name    string
	SigHex  string
	Patches []BytePatch
}

type PatchResult struct {
	Section        string
	VA             uint32
	Applied        bool
	AlreadyPatched bool
}

func parseSig(hexPattern string) (sig, mask []byte, err error) {
	for _, tok := range strings.Fields(hexPattern) {
		if tok == "??" {
			sig = append(sig, 0)
			mask = append(mask, 0)
			continue
		}
		v, err2 := strconv.ParseUint(tok, 16, 8)
		if err2 != nil {
			return nil, nil, fmt.Errorf("bad signature byte %q: %w", tok, err2)
		}
		sig = append(sig, byte(v))
		mask = append(mask, 0xff)
	}
	return sig, mask, nil
}

func findAllSig(data, sig, mask []byte) []int {
	var hits []int
	n := len(sig)
	for i := 0; i+n <= len(data); i += 2 {
		ok := true
		for j := 0; j < n; j++ {
			if mask[j] != 0 && data[i+j] != sig[j] {
				ok = false
				break
			}
		}
		if ok {
			hits = append(hits, i)
		}
	}
	return hits
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ApplyFuncPatch(mod *wince.Module, section string, fp FuncPatch) (*PatchResult, error) {
	sig, mask, err := parseSig(fp.SigHex)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fp.Name, err)
	}

	secs, err := mod.Sections()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", mod.Name, err)
	}

	for _, sec := range secs {
		if sec.Name != section {
			continue
		}
		hits := findAllSig(sec.Data, sig, mask)
		if len(hits) != 1 {
			return nil, fmt.Errorf("signature matching failed, total findings: %d", len(hits))
		}
		hit := hits[0]

		buf := append([]byte(nil), sec.Data...)
		dirty := false

		res := PatchResult{Section: sec.Name, VA: sec.RealAddr + uint32(hit), AlreadyPatched: true}
		var matchErr error

		for _, p := range fp.Patches {
			cur := buf[hit+p.RelOffset : hit+p.RelOffset+len(p.New)]
			switch {
			case bytesEqual(cur, p.New):
				// already patched
			case bytesEqual(cur, p.Old):
				copy(cur, p.New)
				res.Applied = true
				res.AlreadyPatched = false
				dirty = true
			default:
				matchErr = fmt.Errorf("%s: %s+%#x: unexpected bytes at +%#x (want %x or %x, got %x)",
					fp.Name, sec.Name, hit, p.RelOffset, p.Old, p.New, cur)
			}
		}

		if matchErr != nil {
			return nil, matchErr
		}

		if dirty {
			if err := mod.ReplaceSection(sec.Index, buf); err != nil {
				return nil, fmt.Errorf("%s: %s: %w", fp.Name, sec.Name, err)
			}
		}
		return &res, nil
	}

	return nil, fmt.Errorf("could not find section %s for patching", section)
}
