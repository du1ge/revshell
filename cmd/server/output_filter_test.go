package main

import (
	"bytes"
	"testing"
)

func TestScrollbackWriterFiltersClearScrollback(t *testing.T) {
	var buf bytes.Buffer
	w := newScrollbackWriter(&buf)

	input := []byte("hello\x1b[3Jworld")
	if _, err := w.Write(input); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	if got := buf.String(); got != "helloworld" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestScrollbackWriterHandlesSplitSequences(t *testing.T) {
	var buf bytes.Buffer
	w := newScrollbackWriter(&buf)

	if _, err := w.Write([]byte("foo\x1b[")); err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if _, err := w.Write([]byte("3Jbar")); err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	if got := buf.String(); got != "foobar" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestScrollbackWriterLeavesUnrelatedEscapeSequences(t *testing.T) {
	var buf bytes.Buffer
	w := newScrollbackWriter(&buf)

	if _, err := w.Write([]byte("foo\x1b[2Jbar")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	if got := buf.Bytes(); !bytes.Equal(got, []byte("foo\x1b[2Jbar")) {
		t.Fatalf("unexpected output bytes: %v", got)
	}
}
