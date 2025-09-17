package terminal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// Options defines configuration values for an interactive shell session.
type Options struct {
	Prompt     string
	Shell      string
	InitialDir string
}

// Session models an interactive command execution environment backed by a
// pseudo-terminal attached to a real shell on the host machine.
type Session struct {
	reader io.Reader
	writer io.Writer
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
	if !filepath.IsAbs(cwd) {
		if abs, err := filepath.Abs(cwd); err == nil {
			cwd = abs
		}
	}

	return &Session{
		reader: r,
		writer: w,
		opts:   opts,
		cwd:    cwd,
		user:   user,
		host:   host,
	}, nil
}

// Run starts the interactive loop, bridging the encrypted transport with a
// pseudo-terminal attached to the configured shell.
func (s *Session) Run() error {
	if s.closed {
		return errors.New("terminal: session already closed")
	}

	if _, err := io.WriteString(s.writer, "Welcome to the Go remote shell. Type 'exit' to disconnect.\r\n"); err != nil {
		return err
	}

	master, slave, err := openPTY()
	if err != nil {
		return fmt.Errorf("terminal: failed to allocate pty: %w", err)
	}
	defer master.Close()
	defer slave.Close()

	cmd := exec.Command(s.opts.Shell)
	cmd.Env = s.buildEnvironment()
	cmd.Dir = s.cwd
	cmd.Stdout = slave
	cmd.Stdin = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: int(slave.Fd())}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("terminal: failed to start shell: %w", err)
	}
	_ = slave.Close()

	var wg sync.WaitGroup
	var copyErr error
	var copyErrMu sync.Mutex

	recordErr := func(err error) {
		if err == nil || errors.Is(err, io.EOF) {
			return
		}
		if errors.Is(err, os.ErrClosed) {
			return
		}
		var pathErr *os.PathError
		if errors.As(err, &pathErr) && errors.Is(pathErr.Err, os.ErrClosed) {
			return
		}
		copyErrMu.Lock()
		if copyErr == nil {
			copyErr = err
		}
		copyErrMu.Unlock()
	}

	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := io.Copy(s.writer, master)
		recordErr(err)
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(master, s.reader)
		recordErr(err)
		_ = master.Close()
	}()

	waitErr := cmd.Wait()
	wg.Wait()

	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			recordErr(fmt.Errorf("terminal: shell exited with status: %w", exitErr))
		} else {
			recordErr(fmt.Errorf("terminal: shell wait error: %w", waitErr))
		}
	}

	s.closed = true

	return copyErr
}

func (s *Session) buildEnvironment() []string {
	env := os.Environ()
	prompt := s.renderPrompt()
	if prompt != "" {
		env = append(env, fmt.Sprintf("PS1=%s", prompt))
	}
	return env
}

func (s *Session) renderPrompt() string {
	prompt := s.opts.Prompt
	if prompt == "" {
		prompt = "{{.USER}}@{{.HOST}} {{.CWD}}$ "
	}

	prompt = strings.ReplaceAll(prompt, "{{.USER}}", s.user)
	prompt = strings.ReplaceAll(prompt, "{{.HOST}}", s.host)
	prompt = strings.ReplaceAll(prompt, "{{.CWD}}", "\\w")
	prompt = strings.ReplaceAll(prompt, "{{.BASENAME}}", "\\W")

	return prompt
}

func openPTY() (*os.File, *os.File, error) {
	fd, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("terminal: open /dev/ptmx: %w", err)
	}

	if err := unlockPT(fd); err != nil {
		_ = syscall.Close(fd)
		return nil, nil, err
	}

	name, err := ptsName(fd)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, nil, err
	}

	// Ensure the slave node is accessible to the current user.
	_ = syscall.Chown(name, os.Getuid(), os.Getgid())
	_ = syscall.Chmod(name, 0o600)

	slaveFD, err := syscall.Open(name, syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, nil, fmt.Errorf("terminal: open slave pty: %w", err)
	}

	master := os.NewFile(uintptr(fd), "pty-master")
	slave := os.NewFile(uintptr(slaveFD), "pty-slave")
	return master, slave, nil
}

func unlockPT(fd int) error {
	var unlock int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TIOCSPTLCK), uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		return fmt.Errorf("terminal: unlock pty: %w", syscall.Errno(errno))
	}
	return nil
}

func ptsName(fd int) (string, error) {
	var n uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TIOCGPTN), uintptr(unsafe.Pointer(&n))); errno != 0 {
		return "", fmt.Errorf("terminal: ptsname: %w", syscall.Errno(errno))
	}
	return fmt.Sprintf("/dev/pts/%d", n), nil
}
