package c_lz4

/*
#cgo CFLAGS: -O3
#include "lz4.h"
#include "lz4hc.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

// CompressHC compresses src using official LZ4 HC at the specified compression level (typically 12).
func CompressHC(src []byte, level int) ([]byte, error) {
	if len(src) == 0 {
		return nil, nil
	}
	bound := int(C.LZ4_compressBound(C.int(len(src))))
	dst := make([]byte, bound)
	n := int(C.LZ4_compress_HC(
		(*C.char)(unsafe.Pointer(&src[0])),
		(*C.char)(unsafe.Pointer(&dst[0])),
		C.int(len(src)),
		C.int(bound),
		C.int(level),
	))
	if n <= 0 {
		return nil, errors.New("LZ4_compress_HC failed")
	}
	return dst[:n], nil
}

// Decompress decompresses src into a buffer of uncompressedSize bytes.
func Decompress(src []byte, uncompressedSize int) ([]byte, error) {
	if len(src) == 0 {
		return nil, nil
	}
	dst := make([]byte, uncompressedSize)
	n := int(C.LZ4_decompress_safe(
		(*C.char)(unsafe.Pointer(&src[0])),
		(*C.char)(unsafe.Pointer(&dst[0])),
		C.int(len(src)),
		C.int(uncompressedSize),
	))
	if n < 0 || n != uncompressedSize {
		return nil, errors.New("LZ4_decompress_safe failed")
	}
	return dst, nil
}
