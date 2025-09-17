//go:build linux

package main

import (
	"syscall"
	"unsafe"
)

type terminalState struct {
	termios syscall.Termios
}

func isTerminal(fd int) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&termios)))
	return errno == 0
}

func makeRaw(fd int) (*terminalState, error) {
	var old syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&old))); errno != 0 {
		return nil, errno
	}

	newState := old
	newState.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	newState.Oflag &^= syscall.OPOST
	newState.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	newState.Cflag &^= syscall.CSIZE | syscall.PARENB
	newState.Cflag |= syscall.CS8
	newState.Cc[syscall.VMIN] = 1
	newState.Cc[syscall.VTIME] = 0

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&newState))); errno != 0 {
		return nil, errno
	}

	return &terminalState{termios: old}, nil
}

func restore(fd int, state *terminalState) error {
	if state == nil {
		return nil
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&state.termios)))
	if errno != 0 {
		return errno
	}
	return nil
}
