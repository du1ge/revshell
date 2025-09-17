//go:build !linux

package main

const daemonSupported = false

func daemonize() (bool, error) {
	return false, nil
}
