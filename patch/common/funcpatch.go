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
	Name     string
	SigHex   string
	Patches  []BytePatch
	MaxCount int
}

type PatchResult struct {
	FuncPatch      *FuncPatch
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

func ApplyFuncPatches(mod *wince.Module, section string, fps []FuncPatch) ([]PatchResult, error) {
	secs, err := mod.Sections()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", mod.Name, err)
	}

	var sec *wince.Section
	for i := range secs {
		if secs[i].Name == section {
			sec = &secs[i]
			break
		}
	}
	if sec == nil {
		return nil, fmt.Errorf("could not find section %s for patching", section)
	}

	buf := append([]byte(nil), sec.Data...)
	dirty := false
	results := make([]PatchResult, len(fps))

	for i, fp := range fps {
		sig, mask, err := parseSig(fp.SigHex)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fp.Name, err)
		}

		hits := findAllSig(buf, sig, mask)
		if (fp.MaxCount == 0 && len(hits) != 1) || fp.MaxCount > len(hits) {
			return nil, fmt.Errorf("%s: signature matching failed, total findings: %d", fp.Name, len(hits))
		}

		for _, hit := range hits {
			res := PatchResult{FuncPatch: &fp, Section: sec.Name, VA: sec.RealAddr + uint32(hit), AlreadyPatched: true}

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
					return nil, fmt.Errorf("%s: %s+%#x: unexpected bytes at +%#x (want %x or %x, got %x)",
						fp.Name, sec.Name, hit, p.RelOffset, p.Old, p.New, cur)
				}
			}

			results[i] = res
		}
	}

	if dirty {
		if err := mod.ReplaceSection(sec.Index, buf); err != nil {
			return nil, fmt.Errorf("%s: %w", sec.Name, err)
		}
	}
	return results, nil
}

func ApplyFuncPatch(mod *wince.Module, section string, fp FuncPatch) (*PatchResult, error) {
	results, err := ApplyFuncPatches(mod, section, []FuncPatch{fp})
	if err != nil {
		return nil, err
	}
	return &results[0], nil
}
