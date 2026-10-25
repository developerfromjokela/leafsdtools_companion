//go:build integration

package patch

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func findTestImage(envVar string) string {
	if p := os.Getenv(envVar); p != "" {
		if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
			return p
		}
	}
	return ""
}

func TestGoldenZE1Skip(t *testing.T) {
	srcPath := findTestImage("LST_TEST_ZE1_IMAGE")
	if srcPath == "" {
		t.Skip("ZE1 test image not available; set LST_TEST_ZE1_IMAGE to run")
	}

	tmpFile := filepath.Join(t.TempDir(), "ze1-skip.bin")
	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	res, err := ApplyAutoAgreePatch(f, int64(len(data)), ModeSkip, 2000, func(s string) {
		t.Log(s)
	})
	if err != nil {
		t.Fatalf("ApplyAutoAgreePatch failed: %v", err)
	}

	if res.BuildName != "G218ENNI.120" {
		t.Errorf("BuildName = %s, want G218ENNI.120", res.BuildName)
	}
	const expectedSHA = "9d4467fffa36b6028c2127f2e7d06a215e9e95031ef7d7dec7f489a4c0e6889e"
	if res.SHA256 != expectedSHA {
		t.Errorf("SHA256 = %s, want %s", res.SHA256, expectedSHA)
	}

	// Re-patching should return already patched
	_, err = ApplyAutoAgreePatch(f, int64(len(data)), ModeSkip, 2000, nil)
	if err == nil || !strings.Contains(err.Error(), "already patched") {
		t.Errorf("expected 'already patched' on re-patch, got %v", err)
	}
}

func TestGoldenZE1Timer(t *testing.T) {
	srcPath := findTestImage("LST_TEST_ZE1_IMAGE")
	if srcPath == "" {
		t.Skip("ZE1 test image not available; set LST_TEST_ZE1_IMAGE to run")
	}

	tmpFile := filepath.Join(t.TempDir(), "ze1-timer.bin")
	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	res, err := ApplyAutoAgreePatch(f, int64(len(data)), ModeTimer, 2000, func(s string) {
		t.Log(s)
	})
	if err != nil {
		t.Fatalf("ApplyAutoAgreePatch failed: %v", err)
	}

	const expectedSHA = "e3d7436335d30ff74d7a3bd5eef488bafb3fd951036564159f3c68aee5ae4dea"
	if res.SHA256 != expectedSHA {
		t.Errorf("SHA256 = %s, want %s", res.SHA256, expectedSHA)
	}

	// Re-patching with different delay
	_, err = ApplyAutoAgreePatch(f, int64(len(data)), ModeTimer, 3000, nil)
	if err == nil || !strings.Contains(err.Error(), "already patched") {
		t.Errorf("expected 'already patched' on re-patch with different delay, got %v", err)
	}
}

func TestGoldenZE0Skip(t *testing.T) {
	srcPath := findTestImage("LST_TEST_ZE0_IMAGE")
	if srcPath == "" {
		t.Skip("ZE0 test image not available; set LST_TEST_ZE0_IMAGE to run")
	}

	tmpFile := filepath.Join(t.TempDir(), "ze0-skip.bin")
	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	res, err := ApplyAutoAgreePatch(f, int64(len(data)), ModeSkip, 2000, func(s string) {
		t.Log(s)
	})
	if err != nil {
		t.Fatalf("ApplyAutoAgreePatch failed: %v", err)
	}

	if res.BuildName != "G214ELNI.062" {
		t.Errorf("BuildName = %s, want G214ELNI.062", res.BuildName)
	}
	const expectedSHA = "ad998ae9e47483ff8382926a91e88a9a20614ca0e12ac0b3620325689ae24444"
	if res.SHA256 != expectedSHA {
		t.Errorf("SHA256 = %s, want %s", res.SHA256, expectedSHA)
	}
}

type strictSectorReader struct {
	data []byte
}

func (s *strictSectorReader) ReadAt(p []byte, off int64) (int, error) {
	if off%512 != 0 || len(p)%512 != 0 {
		return 0, errors.New("EINVAL: read must be sector-aligned (multiple of 512)")
	}
	if off >= int64(len(s.data)) {
		return 0, os.ErrNotExist
	}
	n := copy(p, s.data[off:])
	return n, nil
}

func TestFindModSectorAlignment(t *testing.T) {
	srcPath := findTestImage("LST_TEST_ZE1_IMAGE")
	if srcPath == "" {
		t.Skip("test image not available; set LST_TEST_ZE1_IMAGE to run")
	}
	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatal(err)
	}

	strict := &strictSectorReader{data: data}
	at, b, err := FindMod(strict, int64(len(data)))
	if err != nil {
		t.Fatalf("FindMod failed on strict sector-aligned device: %v", err)
	}
	if at != 0xac0000 || b.Name != "G218ENNI.120" {
		t.Errorf("FindMod = (%#x, %s), want (0xac0000, G218ENNI.120)", at, b.Name)
	}
}
