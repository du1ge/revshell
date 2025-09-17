//go:build linux

package unix

import (
	"syscall"
	"unsafe"
)

// Winsize mirrors the structure expected by the TIOCGWINSZ/TIOCSWINSZ ioctls.
// See https://man7.org/linux/man-pages/man4/tty_ioctl.4.html for details.
type Winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

const (
	// Values copied from asm-generic/ioctls.h.
	TIOCGWINSZ = 0x5413
	TIOCSWINSZ = 0x5414
)

// IoctlGetWinsize retrieves the window size for the terminal associated with fd.
func IoctlGetWinsize(fd int, req int) (*Winsize, error) {
	var ws Winsize
	if err := ioctl(uintptr(fd), uintptr(req), unsafe.Pointer(&ws)); err != nil {
		return nil, err
	}
	return &ws, nil
}

// IoctlSetWinsize sets the terminal window size for the provided file descriptor.
func IoctlSetWinsize(fd int, req int, ws *Winsize) error {
	return ioctl(uintptr(fd), uintptr(req), unsafe.Pointer(ws))
}

func ioctl(fd uintptr, req uintptr, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}
