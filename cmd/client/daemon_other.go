//go:build !linux

package main

const daemonSupported = false

func daemonize(opts *clientOptions) (bool, error) {
	return false, nil
}

func finalizeDaemonEnvironment() error {
	return nil
}
