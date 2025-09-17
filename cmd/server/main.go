package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"revshell/pkg/secureio"
	"revshell/pkg/terminal"
)

type serverOptions struct {
	listenAddr string
	passphrase string
	cipher     string
	shell      string
	prompt     string
	workdir    string
}

func main() {
	opts := parseFlags()

	listener, err := net.Listen("tcp", opts.listenAddr)
	if err != nil {
		log.Fatalf("server: failed to listen on %s: %v", opts.listenAddr, err)
	}
	defer listener.Close()

	log.Printf("server: listening on %s using %s cipher", opts.listenAddr, opts.cipher)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				log.Printf("server: temporary accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			log.Printf("server: stopping listener due to error: %v", err)
			return
		}

		go handleConnection(conn, opts)
	}
}

func parseFlags() serverOptions {
	available := strings.Join(secureio.ListCipherSuites(), ", ")
	listen := flag.String("listen", "0.0.0.0:2222", "address to listen on")
	pass := flag.String("pass", "", "shared passphrase used to derive encryption keys")
	cipherName := flag.String("cipher", "aes", fmt.Sprintf("cipher suite to use (%s)", available))
	shell := flag.String("shell", "/bin/sh", "shell executable used to run commands")
	prompt := flag.String("prompt", "", "prompt template (supports {{.USER}}, {{.HOST}}, {{.CWD}}, {{.BASENAME}})")
	workdir := flag.String("workdir", "", "initial working directory for new sessions")
	flag.Parse()

	if *pass == "" {
		fmt.Fprintln(os.Stderr, "server: passphrase must be provided via -pass")
		os.Exit(1)
	}

	return serverOptions{
		listenAddr: *listen,
		passphrase: *pass,
		cipher:     *cipherName,
		shell:      *shell,
		prompt:     *prompt,
		workdir:    *workdir,
	}
}

func handleConnection(conn net.Conn, opts serverOptions) {
	defer conn.Close()

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err == nil {
			_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}
	}

	log.Printf("server: accepted connection from %s", conn.RemoteAddr())

	reader, writer, err := secureio.Handshake(conn, true, opts.passphrase, opts.cipher)
	if err != nil {
		log.Printf("server: handshake failed for %s: %v", conn.RemoteAddr(), err)
		return
	}

	sessionOpts := terminal.Options{Prompt: opts.prompt, Shell: opts.shell, InitialDir: opts.workdir}
	session, err := terminal.NewSession(reader, writer, sessionOpts)
	if err != nil {
		log.Printf("server: failed to create session for %s: %v", conn.RemoteAddr(), err)
		return
	}

	if err := session.Run(); err != nil {
		log.Printf("server: session for %s ended with error: %v", conn.RemoteAddr(), err)
	} else {
		log.Printf("server: session for %s closed", conn.RemoteAddr())
	}
}
