//go:build !linux

package main

const daemonSupported = false

func daemonize() error {
	return nil
}
