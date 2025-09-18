package main

import (
	"bytes"
	"io"
)

var clearScrollSequence = []byte{0x1b, '[', '3', 'J'}

// scrollbackWriter strips sequences that clear the terminal scrollback buffer
// while forwarding all other bytes to the wrapped writer. Some remote shells
// emit ESC[3J (e.g. via `clear`) which erases the local scrollback and prevents
// the operator from reviewing long command output using the terminal scrollbar.
// By filtering those sequences we preserve the scrollback history without
// altering on-screen behaviour.
type scrollbackWriter struct {
	dest io.Writer
	buf  []byte
}

func newScrollbackWriter(w io.Writer) *scrollbackWriter {
	return &scrollbackWriter{dest: w}
}

// Write removes any occurrences of ESC[3J from the stream and forwards the
// remaining bytes to the destination writer. Partial matches are buffered so
// split sequences are handled correctly across multiple writes.
func (w *scrollbackWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)

	for {
		idx := bytes.Index(w.buf, clearScrollSequence)
		if idx == -1 {
			break
		}

		if idx > 0 {
			if _, err := w.dest.Write(w.buf[:idx]); err != nil {
				return 0, err
			}
		}

		// Drop the ESC[3J sequence.
		w.buf = w.buf[idx+len(clearScrollSequence):]
	}

	keep := longestSuffixPrefix(w.buf, clearScrollSequence)
	if writeLen := len(w.buf) - keep; writeLen > 0 {
		if _, err := w.dest.Write(w.buf[:writeLen]); err != nil {
			return 0, err
		}
		w.buf = w.buf[writeLen:]
	}

	return len(p), nil
}

// Flush writes any buffered data that may represent the start of a filtered
// sequence but never completed.
func (w *scrollbackWriter) Flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	if _, err := w.dest.Write(w.buf); err != nil {
		return err
	}
	w.buf = nil
	return nil
}

func longestSuffixPrefix(buf, pattern []byte) int {
	max := len(pattern) - 1
	if max <= 0 {
		return 0
	}
	if max > len(buf) {
		max = len(buf)
	}
	for i := max; i > 0; i-- {
		if bytes.Equal(buf[len(buf)-i:], pattern[:i]) {
			return i
		}
	}
	return 0
}
