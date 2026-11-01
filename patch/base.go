package patch

import (
	"errors"
	"io"
)

type ReadWriterAt interface {
	io.ReaderAt
	io.WriterAt
}

type PatcherFunc func(f ReadWriterAt, size int64, log func(string)) error

// Patch Stub
type Patch struct {
	PatchName  string
	PatchImage *[]byte
	Patcher    PatcherFunc
}

var ErrNotImplemented = errors.New("patch: Patcher not implemented")

func (b *Patch) Name() string   { return b.PatchName }
func (b *Patch) Image() *[]byte { return b.PatchImage }

func (b *Patch) ApplyPatch(f ReadWriterAt, size int64, log func(string)) error {
	if b.Patcher == nil {
		return ErrNotImplemented
	}
	if log == nil {
		log = func(string) {}
	}
	return b.Patcher(f, size, log)
}
