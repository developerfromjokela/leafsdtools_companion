package lz4hc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func lcg(n int) []byte {
	out := make([]byte, n)
	x := uint32(1)
	for i := range out {
		x = x*1103515245 + 12345
		out[i] = byte(x >> 16)
	}
	return out
}

func codelike(n int) []byte {
	noise := lcg(4096)
	var out []byte
	for i := 0; len(out) < n; i += 97 {
		out = append(out, noise[i%4000:i%4000+37]...)
		out = append(out, make([]byte, 11)...)
		out = append(out, bytes.Repeat([]byte{0xe1, 0xa0, 0x00, 0x00}, 5)...)
	}
	return out[:n]
}

func repeat(s string, n int) []byte { return bytes.Repeat([]byte(s), n) }

func vector(name string) []byte {
	switch name {
	case "zeros":
		return make([]byte, 200000)
	case "ones":
		return repeat("A", 100000)
	case "abab":
		return repeat("ab", 50000)
	case "abcd":
		return repeat("abcd", 40000)
	case "lcg":
		return lcg(100000)
	case "codelike":
		return codelike(300000)
	case "tiny":
		return []byte("hello")
	case "thirteen":
		return repeat("a", 13)
	}
	panic("unknown vector " + name)
}

// TestReferenceVectors pins the output against liblz4 1.10.0's LZ4_compress_HC at level 12.
func TestReferenceVectors(t *testing.T) {
	tests := []struct {
		name   string
		plain  int
		packed int
		sum    string
	}{
		{"zeros", 200000, 795, "cee35124659b75ee2fa4b53b45167d6f84c45072bc8acff56be4911f5230cffb"},
		{"ones", 100000, 403, "01994b1a575b3a0e348ec3cdfb0a898e3aa3229dbb29aeb2ed3bc11063c10b67"},
		{"abab", 100000, 404, "b7ad66441cd2ed7332cc7ff0e4ea705394b23b9e0675139704c75e790af231bb"},
		{"abcd", 160000, 641, "417a0297d911d299227cdef1116f0ea26d4e0c3731bc58b513ea208c3245eb2b"},
		{"lcg", 100000, 100394, "64555ec8e811b7fcf2f22f1cb30f3b7388b7fa9dcabf52a4004bd01fbfc062aa"},
		{"codelike", 300000, 44334, "b08e2e7a9a8569acc908ef13440fd2efc29b191486152a1ff811448dcbe33cd6"},
		{"tiny", 5, 6, "32f3a6e92fb7ab5720412fc2e0f06601d83beee363e3f7a7a904271c33af5835"},
		{"thirteen", 13, 10, "b6e9e7376cffb276a491684df5c7c45f0304f77abc6b9280de8ee862e353cc50"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := vector(tt.name)
			if len(src) != tt.plain {
				t.Fatalf("vector is %d bytes, expected %d", len(src), tt.plain)
			}
			got := Compress(src)
			if len(got) != tt.packed {
				t.Errorf("packed to %d bytes, liblz4 packs to %d", len(got), tt.packed)
			}
			sum := sha256.Sum256(got)
			if hex.EncodeToString(sum[:]) != tt.sum {
				t.Errorf("packed bytes differ from liblz4's")
			}
			back, err := Uncompress(got, len(src))
			if err != nil {
				t.Fatalf("Uncompress: %v", err)
			}
			if !bytes.Equal(back, src) {
				t.Error("round-trip changed the data")
			}
		})
	}
}

func TestUncompressRejectsDamage(t *testing.T) {
	src := codelike(20000)
	packed := Compress(src)

	if _, err := Uncompress(packed, len(src)+1); err == nil {
		t.Error("accepted a block that decoded to the wrong length")
	}
	if _, err := Uncompress(packed[:len(packed)/2], len(src)); err == nil {
		t.Error("accepted a truncated block")
	}
	if _, err := Uncompress([]byte{0xff}, 1); err == nil {
		t.Error("accepted a literal run that runs off the end")
	}
}
