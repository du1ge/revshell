package terminal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"revshell/pkg/secureio"
)

// Options defines configuration values for an interactive shell session.
type Options struct {
	Prompt     string
	Shell      string
	InitialDir string
}

// Session models an interactive command execution environment backed by a
// local PTY-powered shell process.
type Session struct {
	reader   io.Reader
	writer   io.Writer
	opts     Options
	closed   bool
	resizeCh <-chan secureio.WindowSize
}

// NewSession constructs a new interactive session over the provided reader and
// writer. The reader and writer are typically backed by a secure network
// connection.
func NewSession(r io.Reader, w io.Writer, opts Options) (*Session, error) {
	if opts.Shell == "" {
		opts.Shell = "/bin/sh"
	}

	if opts.InitialDir != "" {
		abs, err := filepath.Abs(opts.InitialDir)
		if err != nil {
			return nil, fmt.Errorf("terminal: resolve initial directory: %w", err)
		}
		opts.InitialDir = abs
	}

	return &Session{
		reader: r,
		writer: w,
		opts:   opts,
	}, nil
}

// SetResizeEvents registers a channel delivering terminal resize notifications
// from the remote peer. Notifications are forwarded to the PTY when the
// session starts running.
func (s *Session) SetResizeEvents(ch <-chan secureio.WindowSize) {
	s.resizeCh = ch
}

// Run starts the interactive loop, wiring the remote stream to a PTY-backed
// shell process on the local machine.
func (s *Session) Run() error {
	if s.closed {
		return errors.New("terminal: session already closed")
	}

	cmd := exec.Command(s.opts.Shell)
	cmd.Env = os.Environ()
	if s.opts.InitialDir != "" {
		cmd.Dir = s.opts.InitialDir
	}

	if prompt := s.promptPS1(); prompt != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("PS1=%s", prompt))
	}

	cmd.Env = append(cmd.Env, "TERM=xterm-256color")

	ptmx, err := startPTY(cmd)
	if err != nil {
		return fmt.Errorf("terminal: start shell: %w", err)
	}
	defer func() { _ = ptmx.Close() }()

	errCh := make(chan error, 2)

	if s.resizeCh != nil {
		go func(ch <-chan secureio.WindowSize, f *os.File) {
			for size := range ch {
				if size.Rows == 0 || size.Cols == 0 {
					continue
				}
				if err := resizePTY(f, size.Rows, size.Cols); err != nil {
					fmt.Fprintf(os.Stderr, "terminal: failed to resize pty: %v\n", err)
				}
			}
		}(s.resizeCh, ptmx)
	}

	go func() {
		_, err := io.Copy(s.writer, ptmx)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(ptmx, s.reader)
		errCh <- err
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) && firstErr == nil {
			firstErr = err
		}
	}

	_ = ptmx.Close()

	if err := cmd.Wait(); err != nil {
		if firstErr == nil {
			firstErr = err
		}
	}

	s.closed = true

	if firstErr != nil && !errors.Is(firstErr, io.EOF) && !errors.Is(firstErr, os.ErrClosed) {
		return firstErr
	}

	return nil
}

func (s *Session) promptPS1() string {
	if s.opts.Prompt == "" {
		return ""
	}

	prompt := s.opts.Prompt
	prompt = strings.ReplaceAll(prompt, "{{.USER}}", "\\u")
	prompt = strings.ReplaceAll(prompt, "{{.HOST}}", "\\h")
	prompt = strings.ReplaceAll(prompt, "{{.CWD}}", "\\w")
	prompt = strings.ReplaceAll(prompt, "{{.BASENAME}}", "\\W")
	prompt = strings.ReplaceAll(prompt, "\n", "\\n")
	return prompt
}
