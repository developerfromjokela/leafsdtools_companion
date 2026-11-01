package qy8consent

import (
	"fmt"
	"io"
	"math"
	"unsafe"
)

const directAlign = 4096

type directAware interface{ DirectIO() bool }

type alignedAt struct {
	rw   ReadWriterAt
	size int64
}

func directReader(r io.ReaderAt, size int64) io.ReaderAt {
	d, ok := r.(directAware)
	if !ok || !d.DirectIO() {
		return r
	}
	rw, ok := r.(ReadWriterAt)
	if !ok {
		return &alignedReaderAt{r: r, size: size}
	}
	return &alignedAt{rw: rw, size: size}
}

func directReadWriter(rw ReadWriterAt, size int64) ReadWriterAt {
	d, ok := rw.(directAware)
	if !ok || !d.DirectIO() {
		return rw
	}
	return &alignedAt{rw: rw, size: size}
}

type alignedReaderAt struct {
	r    io.ReaderAt
	size int64
}

func (a *alignedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	return alignedReadAt(a.r, a.size, p, off)
}

func (a *alignedAt) ReadAt(p []byte, off int64) (int, error) {
	return alignedReadAt(a.rw, a.size, p, off)
}

func (a *alignedAt) WriteAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	start, end, err := alignedRange(off, len(p), a.size)
	if err != nil {
		return 0, err
	}
	buf := alignedBuffer(int(end - start))
	if n, err := a.rw.ReadAt(buf, start); err != nil {
		return 0, err
	} else if n != len(buf) {
		return 0, io.ErrUnexpectedEOF
	}
	copy(buf[off-start:], p)
	if n, err := a.rw.WriteAt(buf, start); err != nil {
		return 0, err
	} else if n != len(buf) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func (a *alignedAt) Sync() error {
	s, ok := a.rw.(syncer)
	if !ok {
		return fmt.Errorf("target does not support sync")
	}
	return s.Sync()
}

func alignedReadAt(r io.ReaderAt, size int64, p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	start, end, err := alignedRange(off, len(p), size)
	if err != nil {
		return 0, err
	}
	buf := alignedBuffer(int(end - start))
	if n, err := r.ReadAt(buf, start); err != nil {
		return 0, err
	} else if n != len(buf) {
		return 0, io.ErrUnexpectedEOF
	}
	copy(p, buf[off-start:off-start+int64(len(p))])
	return len(p), nil
}

func alignedRange(off int64, length int, size int64) (int64, int64, error) {
	if off < 0 || off > math.MaxInt64-int64(length) {
		return 0, 0, fmt.Errorf("I/O range out of bounds")
	}
	start := off / directAlign * directAlign
	end := (off + int64(length) + directAlign - 1) / directAlign * directAlign
	if size > 0 && end > size {
		return 0, 0, fmt.Errorf("aligned I/O range exceeds device size")
	}
	return start, end, nil
}

func alignedBuffer(size int) []byte {
	b := make([]byte, size+directAlign)
	addr := uintptr(unsafe.Pointer(&b[0]))
	skip := int((-addr) & (directAlign - 1))
	return b[skip : skip+size : skip+size]
}
