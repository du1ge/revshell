package terminal

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// SendOptions transmits the provided session options over the writer using a
// single JSON line.
func SendOptions(w io.Writer, opts Options) error {
	data, err := json.Marshal(opts)
	if err != nil {
		return fmt.Errorf("terminal: marshal session options: %w", err)
	}

	payload := append(data, '\n')
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("terminal: send session options: %w", err)
	}
	return nil
}

// ReceiveOptions reads a single line JSON payload from the reader and decodes
// it into session options.
func ReceiveOptions(r *bufio.Reader) (Options, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return Options{}, fmt.Errorf("terminal: read session options: %w", err)
	}

	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return Options{}, fmt.Errorf("terminal: empty session options payload")
	}

	var opts Options
	if err := json.Unmarshal(line, &opts); err != nil {
		return Options{}, fmt.Errorf("terminal: decode session options: %w", err)
	}
	return opts, nil
}
