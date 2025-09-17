//go:build linux

package main

import (
	"io"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const daemonSupported = true

func daemonize(opts *clientOptions) (bool, error) {
	if opts.daemonized {
		return false, nil
	}

	nullFile, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return false, err
	}
	defer nullFile.Close()

	args := make([]string, 0, len(os.Args)+1)
	args = append(args, os.Args[1:]...)
	args = append(args, "--daemonized")

	cmd := exec.Command(os.Args[0], args...)
	cmd.Stdout = nullFile
	cmd.Stderr = nullFile
	cmd.Stdin = nullFile
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return false, err
	}
	if err := cmd.Process.Release(); err != nil {
		return false, err
	}

	return true, nil
}

func finalizeDaemonEnvironment() error {
	if err := os.Chdir("/"); err != nil {
		return err
	}
	// Reset the file mode creation mask to a known state.
	syscall.Umask(0)

	writer, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, filepath.Base(os.Args[0]))
	if err != nil {
		log.SetOutput(io.Discard)
	} else {
		log.SetOutput(writer)
	}
	log.SetFlags(log.LstdFlags)

	return nil
}
