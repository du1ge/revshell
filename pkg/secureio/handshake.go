package secureio

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

const (
	frameTypeData       = 0x01
	frameTypeAuth       = 0x02
	frameTypeAuthOK     = 0x03
	frameTypeAuthReject = 0x04

	maxFramePayload = 32 * 1024
)

// Handshake establishes an encrypted AES-GCM transport on top of conn and
// performs password authentication. The same AES key and authentication
// password must be provided on both sides of the connection.
func Handshake(conn net.Conn, isServer bool, aesKey, authPassword string) (io.Reader, io.Writer, error) {
	if aesKey == "" {
		return nil, nil, errors.New("secureio: AES key must be provided")
	}
	if authPassword == "" {
		return nil, nil, errors.New("secureio: authentication password must be provided")
	}

	serverNonce := make([]byte, 32)
	clientNonce := make([]byte, 32)

	if isServer {
		if _, err := rand.Read(serverNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: generate server nonce: %w", err)
		}
		if _, err := conn.Write(serverNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: send server nonce: %w", err)
		}
		if _, err := io.ReadFull(conn, clientNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: read client nonce: %w", err)
		}
	} else {
		if _, err := io.ReadFull(conn, serverNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: read server nonce: %w", err)
		}
		if _, err := rand.Read(clientNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: generate client nonce: %w", err)
		}
		if _, err := conn.Write(clientNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: send client nonce: %w", err)
		}
	}

	sessionKey := deriveSessionKey(aesKey, serverNonce, clientNonce)
	transport, err := newGCMTransport(conn, sessionKey)
	if err != nil {
		return nil, nil, err
	}

	expectedAuth := deriveAuthDigest(authPassword, serverNonce, clientNonce)

	if isServer {
		frameType, payload, err := transport.readFrame()
		if err != nil {
			return nil, nil, fmt.Errorf("secureio: read auth frame: %w", err)
		}
		if frameType != frameTypeAuth {
			return nil, nil, fmt.Errorf("secureio: unexpected frame type %d during authentication", frameType)
		}
		if subtle.ConstantTimeCompare(payload, expectedAuth[:]) != 1 {
			_ = transport.writeFrame(frameTypeAuthReject, nil)
			return nil, nil, errors.New("secureio: authentication failed")
		}
		if err := transport.writeFrame(frameTypeAuthOK, nil); err != nil {
			return nil, nil, fmt.Errorf("secureio: send auth acknowledgement: %w", err)
		}
	} else {
		if err := transport.writeFrame(frameTypeAuth, expectedAuth[:]); err != nil {
			return nil, nil, fmt.Errorf("secureio: send auth frame: %w", err)
		}
		frameType, _, err := transport.readFrame()
		if err != nil {
			return nil, nil, fmt.Errorf("secureio: read auth response: %w", err)
		}
		if frameType != frameTypeAuthOK {
			return nil, nil, errors.New("secureio: authentication rejected by server")
		}
	}

	reader := &gcmReader{transport: transport}
	writer := &gcmWriter{transport: transport}
	return reader, writer, nil
}

func deriveSessionKey(aesKey string, serverNonce, clientNonce []byte) []byte {
	h := sha256.New()
	h.Write([]byte("revshell/aes-gcm"))
	h.Write([]byte(aesKey))
	h.Write(serverNonce)
	h.Write(clientNonce)
	return h.Sum(nil)
}

func deriveAuthDigest(password string, serverNonce, clientNonce []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("revshell/auth"))
	h.Write([]byte(password))
	h.Write(serverNonce)
	h.Write(clientNonce)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

type gcmTransport struct {
	conn    net.Conn
	gcm     cipher.AEAD
	readBuf []byte
	writeMu sync.Mutex
}

func newGCMTransport(conn net.Conn, key []byte) (*gcmTransport, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secureio: create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secureio: create AES-GCM: %w", err)
	}
	return &gcmTransport{conn: conn, gcm: gcm}, nil
}

func (t *gcmTransport) readFrame() (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(t.conn, header); err != nil {
		return 0, nil, err
	}
	frameType := header[0]
	cipherLen := binary.BigEndian.Uint32(header[1:])
	nonceSize := t.gcm.NonceSize()
	if cipherLen > maxFramePayload+uint32(t.gcm.Overhead()) {
		return 0, nil, fmt.Errorf("secureio: encrypted frame too large: %d bytes", cipherLen)
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(t.conn, nonce); err != nil {
		return 0, nil, err
	}
	ciphertext := make([]byte, cipherLen)
	if _, err := io.ReadFull(t.conn, ciphertext); err != nil {
		return 0, nil, err
	}
	payload, err := t.gcm.Open(nil, nonce, ciphertext, []byte{frameType})
	if err != nil {
		return 0, nil, fmt.Errorf("secureio: decrypt frame: %w", err)
	}
	return frameType, payload, nil
}

func (t *gcmTransport) writeFrame(frameType byte, payload []byte) error {
	if len(payload) > maxFramePayload {
		return fmt.Errorf("secureio: frame payload too large: %d bytes", len(payload))
	}

	nonce := make([]byte, t.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("secureio: generate nonce: %w", err)
	}

	ciphertext := t.gcm.Seal(nil, nonce, payload, []byte{frameType})

	header := make([]byte, 5)
	header[0] = frameType
	binary.BigEndian.PutUint32(header[1:], uint32(len(ciphertext)))

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if _, err := t.conn.Write(header); err != nil {
		return err
	}
	if _, err := t.conn.Write(nonce); err != nil {
		return err
	}
	if _, err := t.conn.Write(ciphertext); err != nil {
		return err
	}
	return nil
}

func (t *gcmTransport) Read(p []byte) (int, error) {
	for len(t.readBuf) == 0 {
		frameType, payload, err := t.readFrame()
		if err != nil {
			return 0, err
		}
		if frameType != frameTypeData {
			return 0, fmt.Errorf("secureio: unexpected frame type %d while reading", frameType)
		}
		if len(payload) == 0 {
			continue
		}
		t.readBuf = payload
	}

	n := copy(p, t.readBuf)
	t.readBuf = t.readBuf[n:]
	return n, nil
}

func (t *gcmTransport) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxFramePayload {
			chunk = p[:maxFramePayload]
		}
		if err := t.writeFrame(frameTypeData, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

type gcmReader struct {
	transport *gcmTransport
}

func (r *gcmReader) Read(p []byte) (int, error) {
	return r.transport.Read(p)
}

type gcmWriter struct {
	transport *gcmTransport
}

func (w *gcmWriter) Write(p []byte) (int, error) {
	return w.transport.Write(p)
}
