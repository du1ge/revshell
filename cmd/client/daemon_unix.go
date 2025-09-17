//go:build !windows && !plan9

package main

import (
	"fmt"
	"os"
	"syscall"
)

const daemonEnvKey = "REVSH_CLIENT_DAEMONIZED"

func daemonize() error {
	if os.Getenv(daemonEnvKey) == "1" {
		return nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	args := append([]string{exePath}, os.Args[1:]...)

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", os.DevNull, err)
	}

	env := append(os.Environ(), daemonEnvKey+"=1")
	attr := &syscall.ProcAttr{
		Env:   env,
		Files: []uintptr{devNull.Fd(), devNull.Fd(), devNull.Fd()},
		Sys: &syscall.SysProcAttr{
			Setsid: true,
		},
	}

	if _, err := syscall.ForkExec(exePath, args, attr); err != nil {
		devNull.Close()
		return fmt.Errorf("fork exec: %w", err)
	}

	devNull.Close()
	os.Exit(0)
	return nil
}
