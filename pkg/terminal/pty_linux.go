//go:build linux

package terminal

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

const (
	_TIOCGPTN   = 0x80045430
	_TIOCSPTLCK = 0x40045431
)

func startPTY(cmd *exec.Cmd) (*os.File, error) {
	fd, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("terminal: open ptmx: %w", err)
	}

	master := os.NewFile(uintptr(fd), "/dev/ptmx")

	unlock := uint32(0)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), uintptr(_TIOCSPTLCK), uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		master.Close()
		return nil, fmt.Errorf("terminal: unlock ptmx: %w", errno)
	}

	var ptyNumber uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), uintptr(_TIOCGPTN), uintptr(unsafe.Pointer(&ptyNumber))); errno != 0 {
		master.Close()
		return nil, fmt.Errorf("terminal: get pty number: %w", errno)
	}

	slavePath := fmt.Sprintf("/dev/pts/%d", ptyNumber)
	slave, err := os.OpenFile(slavePath, os.O_RDWR, 0)
	if err != nil {
		master.Close()
		return nil, fmt.Errorf("terminal: open slave pty: %w", err)
	}
	defer slave.Close()

	cmd.Stdout = slave
	cmd.Stdin = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setctty: true,
		Setsid:  true,
		Ctty:    0,
	}

	if err := cmd.Start(); err != nil {
		master.Close()
		return nil, fmt.Errorf("terminal: start command: %w", err)
	}

	return master, nil
}
