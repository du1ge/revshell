package terminal

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Options defines configuration values for an interactive shell session.
type Options struct {
	Prompt     string
	Shell      string
	InitialDir string
}

// Session models an interactive command execution environment similar to an
// SSH shell.
type Session struct {
	rw     *bufio.ReadWriter
	opts   Options
	cwd    string
	user   string
	host   string
	closed bool
}

// NewSession constructs a new interactive session over the provided reader and
// writer. The reader and writer are typically backed by a secure network
// connection.
func NewSession(r io.Reader, w io.Writer, opts Options) (*Session, error) {
	if opts.Shell == "" {
		opts.Shell = "/bin/sh"
	}

	user := os.Getenv("USER")
	if user == "" {
		user = "user"
	}

	host, err := os.Hostname()
	if err != nil {
		host = "localhost"
	}

	cwd := opts.InitialDir
	if cwd == "" {
		if home := os.Getenv("HOME"); home != "" {
			cwd = home
		} else if pwd, err := os.Getwd(); err == nil {
			cwd = pwd
		} else {
			cwd = "/"
		}
	}

	return &Session{
		rw:   bufio.NewReadWriter(bufio.NewReader(r), bufio.NewWriter(w)),
		opts: opts,
		cwd:  cwd,
		user: user,
		host: host,
	}, nil
}

// Run starts the interactive loop, reading commands from the client and
// returning when the client disconnects or explicitly exits the session.
func (s *Session) Run() error {
	if s.closed {
		return errors.New("terminal: session already closed")
	}
	if err := s.writeLine("Welcome to the Go remote shell. Type 'exit' to disconnect."); err != nil {
		return err
	}

	for {
		if err := s.writePrompt(); err != nil {
			return err
		}

		line, err := s.rw.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		command := strings.TrimRight(line, "\r\n")
		if command == "" {
			continue
		}

		if command == "exit" {
			if err := s.writeLine("Bye!"); err != nil {
				return err
			}
			s.closed = true
			return nil
		}

		if strings.HasPrefix(command, "cd") {
			if err := s.handleCD(command); err != nil {
				if err := s.writeLine(err.Error()); err != nil {
					return err
				}
			}
			continue
		}

		output, execErr := s.executeCommand(command)
		if output != "" {
			if err := s.writeString(output); err != nil {
				return err
			}
		}
		if execErr != nil {
			if err := s.writeLine(execErr.Error()); err != nil {
				return err
			}
		}
	}
}

func (s *Session) executeCommand(command string) (string, error) {
	cmd := exec.Command(s.opts.Shell, "-c", command)
	cmd.Env = os.Environ()
	cmd.Dir = s.cwd
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (s *Session) handleCD(command string) error {
	trimmed := strings.TrimSpace(command)
	if trimmed == "cd" {
		if home := os.Getenv("HOME"); home != "" {
			s.cwd = home
			return nil
		}
		return errors.New("terminal: HOME not set")
	}

	parts := strings.Fields(trimmed)
	if len(parts) < 2 {
		return errors.New("terminal: cd requires a target directory")
	}

	target := parts[1]
	if strings.HasPrefix(target, "~") {
		if home := os.Getenv("HOME"); home != "" {
			switch {
			case target == "~":
				target = home
			case strings.HasPrefix(target, "~/"):
				target = filepath.Join(home, target[2:])
			}
		}
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(s.cwd, target)
	}

	resolved, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("terminal: resolve directory: %w", err)
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("terminal: cd: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("terminal: %s is not a directory", resolved)
	}

	s.cwd = resolved
	return nil
}

func (s *Session) writePrompt() error {
	prompt := s.opts.Prompt
	if prompt == "" {
		prompt = "{{.USER}}@{{.HOST}} {{.CWD}}$ "
	}

	prompt = strings.ReplaceAll(prompt, "{{.USER}}", s.user)
	prompt = strings.ReplaceAll(prompt, "{{.HOST}}", s.host)
	prompt = strings.ReplaceAll(prompt, "{{.CWD}}", s.cwd)
	prompt = strings.ReplaceAll(prompt, "{{.BASENAME}}", filepath.Base(s.cwd))

	if _, err := s.rw.WriteString(prompt); err != nil {
		return err
	}
	return s.rw.Flush()
}

func (s *Session) writeLine(text string) error {
	if _, err := s.rw.WriteString(text + "\n"); err != nil {
		return err
	}
	return s.rw.Flush()
}

func (s *Session) writeString(text string) error {
	if _, err := s.rw.WriteString(text); err != nil {
		return err
	}
	return s.rw.Flush()
}
