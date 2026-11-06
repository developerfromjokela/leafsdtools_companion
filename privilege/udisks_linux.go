//go:build linux

package privilege

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unsafe"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// DirectCapableFile wraps a device fd obtained from UDisks2 and reports
// whether it was actually opened with O_DIRECT.
type DirectCapableFile struct {
	*os.File
	direct bool
}

// DirectIO reports whether writes/reads on this file bypass the page cache
// (opened with O_DIRECT).
func (d *DirectCapableFile) DirectIO() bool { return d.direct }

func blockDeviceSize(f *os.File) (int64, error) {
	var size uint64
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.BLKGETSIZE64, uintptr(unsafe.Pointer(&size)))
	if errno != 0 {
		return 0, errno
	}
	return int64(size), nil
}

func openViaUDisks2(devicePath, mode string, tryDirect bool) (*DirectCapableFile, int64, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, 0, fmt.Errorf("connecting to D-Bus system bus: %w", err)
	}
	defer conn.Close()

	blockPath := udisks2BlockObjectPath(devicePath)
	obj := conn.Object("org.freedesktop.UDisks2", blockPath)

	open := func(flags int32) (dbus.UnixFD, error) {
		options := map[string]dbus.Variant{}
		if flags != 0 {
			options["flags"] = dbus.MakeVariant(flags)
		}
		var fd dbus.UnixFD
		call := obj.Call("org.freedesktop.UDisks2.Block.OpenDevice", 0, mode, options)
		if call.Err != nil {
			return 0, call.Err
		}
		if err := call.Store(&fd); err != nil {
			return 0, err
		}
		return fd, nil
	}

	var (
		fd      dbus.UnixFD
		direct  bool
		openErr error
	)

	if tryDirect && mode != "r" {
		if f, derr := open(int32(unix.O_DIRECT | unix.O_EXCL)); derr == nil {
			fd = f
			direct = true
		} else {
			openErr = derr
		}
	}

	if !direct {
		f, derr := open(0)
		if derr != nil {
			if openErr != nil {
				return nil, 0, fmt.Errorf("udisks2 OpenDevice(%s, %s) failed with O_DIRECT (%v) and without it: %w", blockPath, mode, openErr, derr)
			}
			return nil, 0, fmt.Errorf("udisks2 OpenDevice(%s, %s): %w", blockPath, mode, derr)
		}
		fd = f
	}

	f := os.NewFile(uintptr(fd), devicePath)
	var size int64
	if fi, statErr := f.Stat(); statErr == nil {
		size = fi.Size()
	}
	if size <= 0 {
		if sz, szErr := blockDeviceSize(f); szErr == nil {
			size = sz
		}
	}
	return &DirectCapableFile{File: f, direct: direct}, size, nil
}

func udisks2BlockObjectPath(devicePath string) dbus.ObjectPath {
	name := devicePath
	if idx := strings.LastIndex(devicePath, "/"); idx != -1 {
		name = devicePath[idx+1:]
	}
	return dbus.ObjectPath("/org/freedesktop/UDisks2/block_devices/" + name)
}

var _ io.ReadWriteCloser = (*DirectCapableFile)(nil)
