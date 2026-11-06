package disk

import (
	"LeafSDTools_Companion/privilege"
	"LeafSDTools_Companion/utils"
	"bytes"
	"fmt"
	"io"
	"os"
	"time"
)

type Device struct {
	Path string
	Name string
	Size int64
}

const (
	MaxDiskSize   = 130 * 1000 * 1000 * 1000
	directIOAlign = 4096
)

func (d Device) String() string {
	if d.Size > 0 {
		return fmt.Sprintf("%s (%s) — %s", d.Name, d.Path, utils.HumanSize(d.Size))
	}
	return fmt.Sprintf("%s (%s)", d.Name, d.Path)
}

func OpenDeviceForRead(path string) (io.ReadCloser, int64, error) {
	if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
		f, err := os.Open(path)
		if err != nil {
			return nil, 0, err
		}
		return f, fi.Size(), nil
	}
	return privilege.OpenElevatedDeviceRead(path)
}

func OpenDeviceForReadWrite(path string) (io.ReadWriteCloser, int64, error) {
	if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return nil, 0, err
		}
		return f, fi.Size(), nil
	}
	return privilege.OpenElevatedDeviceReadWrite(path)
}

func DeviceSize(f *os.File) (int64, error) {
	if fi, err := f.Stat(); err == nil && fi.Size() > 0 {
		return fi.Size(), nil
	}
	return deviceSizePlatform(f)
}

func ListDevices() ([]Device, error) {
	return listDevicesPlatform()
}

func UnmountDevice(path string) error {
	return unmountDevicePlatform(path)
}

type ProgressFunc func(written, total int64, rate float64)

// directIOAware implemented by device handles that may have been opened
// with O_DIRECT
type directIOAware interface{ DirectIO() bool }

// fdGetter is implemented by *os.File and anything embedding it.
type fdGetter interface{ Fd() uintptr }

func CreateDiskImage(srcPath, dstPath string, bufSize int, progress ProgressFunc, cancel <-chan struct{}) error {
	hold, err := HoldDeviceVolumes(srcPath)
	if err != nil {
		return fmt.Errorf("preparing source %q: %w", srcPath, err)
	}
	defer hold.Close()

	in, total, err := OpenDeviceForRead(srcPath)
	if err != nil {
		return fmt.Errorf("opening source %q: %w", srcPath, err)
	}
	defer in.Close()

	if total <= 0 {
		if f, ok := in.(*os.File); ok {
			if sz, szErr := DeviceSize(f); szErr == nil {
				total = sz
			}
		}
	}
	if total <= 0 {
		if devs, lerr := ListDevices(); lerr == nil {
			for _, d := range devs {
				if d.Path == srcPath {
					total = d.Size
					break
				}
			}
		}
	}
	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("creating destination %q: %w", dstPath, err)
	}
	defer out.Close()

	return copyStream(in, out, total, bufSize, false, progress, cancel)
}

func RestoreDiskImage(imgPath, devicePath string, bufSize int, verify bool, progress ProgressFunc, cancel <-chan struct{}) error {
	hold, err := HoldDeviceVolumes(devicePath)
	if err != nil {
		return fmt.Errorf("preparing device %q: %w", devicePath, err)
	}
	defer hold.Close()

	in, total, err := OpenDeviceForRead(imgPath)
	if err != nil {
		return fmt.Errorf("opening image %q: %w", imgPath, err)
	}
	defer in.Close()

	out, _, err := OpenDeviceForReadWrite(devicePath)
	if err != nil {
		return fmt.Errorf("opening device %q: %w", devicePath, err)
	}
	defer out.Close()

	direct := false
	if d, ok := out.(directIOAware); ok {
		direct = d.DirectIO()
	}

	// On cancel, close endpoints so a blocked Read/Write unblocks.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-cancel:
			_ = in.Close()
			_ = out.Close()
		case <-done:
		}
	}()

	if err := copyStream(in, out, total, bufSize, direct, progress, cancel); err != nil {
		return err
	}

	_ = syncDevice(out, total, progress, cancel)

	if !verify {
		return nil
	}

	seeker, ok := out.(io.Seeker)
	if !ok {
		return fmt.Errorf("device does not support seek; cannot verify")
	}
	if _, err := seeker.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seeking device for verify: %w", err)
	}

	// Drop any cached pages for the range we just wrote so a verify read
	// can't be silently satisfied from cache instead of physical media.
	if fg, ok := out.(fdGetter); ok {
		dropCachedPages(fg.Fd(), total)
	}

	img2, err := os.Open(imgPath)
	if err != nil {
		return fmt.Errorf("reopening image for verify: %w", err)
	}
	defer img2.Close()

	if progress != nil {
		progress(0, total, 0)
	}

	// Read can block forever. Only compare exactly "total" bytes from the image.
	var deviceReader io.Reader = out
	if total > 0 {
		deviceReader = io.LimitReader(out, total)
	}
	return verifyStream(io.LimitReader(img2, total), deviceReader, total, bufSize, direct, progress, cancel)
}

// syncDevice flushes out to the physical device.
func syncDevice(out io.Writer, total int64, progress ProgressFunc, cancel <-chan struct{}) error {
	syncer, ok := out.(interface{ Sync() error })
	if !ok {
		return nil
	}

	syncDone := make(chan error, 1)
	go func() { syncDone <- syncer.Sync() }()

	start := time.Now()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	const maxWait = 15 * time.Minute
	deadline := time.After(maxWait)

	for {
		select {
		case err := <-syncDone:
			if err != nil {
				return fmt.Errorf("syncing device: %w", err)
			}
			return nil
		case <-ticker.C:
			if progress != nil {
				progress(-1, total, time.Since(start).Seconds())
			}
		case <-deadline:
			return fmt.Errorf("device did not finish flushing writes to media after %s - it may have failed or disconnected", maxWait)
		case <-cancel:
			return fmt.Errorf("cancelled during sync")
		}
	}
}

func copyStream(in io.Reader, out io.Writer, total int64, bufSize int, direct bool, progress ProgressFunc, cancel <-chan struct{}) error {
	if bufSize <= 0 {
		bufSize = 4 * 1024 * 1024
	}
	// for O_DIRECT.
	if bufSize%directIOAlign != 0 {
		bufSize = (bufSize/directIOAlign + 1) * directIOAlign
	}
	var buf []byte
	if direct {
		buf = alignedBuffer(bufSize)
	} else {
		buf = make([]byte, bufSize)
	}

	var written int64
	start := time.Now()
	lastReport := start

	report := func() {
		if progress == nil {
			return
		}
		elapsed := time.Since(start).Seconds()
		var rate float64
		if elapsed > 0 {
			rate = float64(written) / elapsed
		}
		progress(written, total, rate)
	}

	for {
		select {
		case <-cancel:
			return fmt.Errorf("cancelled after %s written", utils.HumanSize(written))
		default:
		}

		n, rerr := in.Read(buf)
		if n > 0 {
			writeBuf := buf[:n]

			// O_DIRECT requires the write length to be a multiple of
			// directIOAlign. The final chunk of an image whose size isn't
			// an exact multiple of it can't satisfy that, so fall back to
			// buffered I/O for just that last write.
			if direct && n%directIOAlign != 0 {
				if fg, ok := out.(fdGetter); ok {
					if clrErr := clearDirectIO(fg.Fd()); clrErr == nil {
						direct = false
					}
				}
			}

			off := 0
			for off < n {
				nw, werr := out.Write(writeBuf[off:])
				if nw > 0 {
					off += nw
					written += int64(nw)
				}
				if werr != nil {
					return fmt.Errorf("writing at offset %d: %w", written, werr)
				}
				if nw == 0 {
					return fmt.Errorf("writing at offset %d: short write", written)
				}
			}
			if time.Since(lastReport) > 300*time.Millisecond {
				report()
				lastReport = time.Now()
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("reading at offset %d: %w", written, rerr)
		}
	}
	report()
	return nil
}

func verifyStream(expected io.Reader, actual io.Reader, total int64, bufSize int, direct bool, progress ProgressFunc, cancel <-chan struct{}) error {
	if bufSize <= 0 {
		bufSize = 4 * 1024 * 1024
	}
	if bufSize%directIOAlign != 0 {
		bufSize = (bufSize/directIOAlign + 1) * directIOAlign
	}
	var a, b []byte
	if direct {
		a = alignedBuffer(bufSize)
		b = alignedBuffer(bufSize)
	} else {
		a = make([]byte, bufSize)
		b = make([]byte, bufSize)
	}

	var checked int64
	start := time.Now()
	lastReport := start

	report := func() {
		if progress == nil {
			return
		}
		elapsed := time.Since(start).Seconds()
		var rate float64
		if elapsed > 0 {
			rate = float64(checked) / elapsed
		}
		progress(checked, total, rate)
	}

	for {
		select {
		case <-cancel:
			return fmt.Errorf("verify cancelled after %s checked", utils.HumanSize(checked))
		default:
		}

		if total > 0 && checked >= total {
			report()
			return nil
		}

		toRead := len(a)
		if total > 0 {
			remain := total - checked
			if remain < int64(toRead) {
				toRead = int(remain)
			}
		}
		if toRead <= 0 {
			report()
			return nil
		}

		na, erra := io.ReadFull(expected, a[:toRead])
		nb, errb := io.ReadFull(actual, b[:toRead])

		n := na
		if nb < n {
			n = nb
		}
		if n > 0 {
			if !bytes.Equal(a[:n], b[:n]) {
				for i := 0; i < n; i++ {
					if a[i] != b[i] {
						return fmt.Errorf("verify mismatch at offset %d (image 0x%02x vs device 0x%02x)", checked+int64(i), a[i], b[i])
					}
				}
			}
			checked += int64(n)
			if time.Since(lastReport) > 300*time.Millisecond {
				report()
				lastReport = time.Now()
			}
		}

		if checked >= total && total > 0 {
			report()
			return nil
		}

		if erra == io.EOF || erra == io.ErrUnexpectedEOF {
			if errb == io.EOF || errb == io.ErrUnexpectedEOF || errb == nil {
				report()
				return nil
			}
			return fmt.Errorf("verify: device read error at offset %d: %w", checked, errb)
		}
		if erra != nil {
			return fmt.Errorf("verify: image read error at offset %d: %w", checked, erra)
		}
		if errb == io.EOF || errb == io.ErrUnexpectedEOF {
			return fmt.Errorf("verify: device shorter than image at offset %d", checked)
		}
		if errb != nil {
			return fmt.Errorf("verify: device read error at offset %d: %w", checked, errb)
		}
	}
}
