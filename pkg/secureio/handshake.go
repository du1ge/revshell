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
	frameTypeWindowSize = 0x05

	maxFramePayload = 32 * 1024
)

// WindowSize represents the row/column dimensions of an interactive terminal.
type WindowSize struct {
	Rows uint16
	Cols uint16
}

// Transport exposes the encrypted data stream established during the
// handshake along with helpers for control frames such as terminal resizes.
type Transport struct {
	transport *gcmTransport
	reader    *gcmReader
	writer    *gcmWriter
}

// Reader returns the encrypted data reader associated with the transport.
func (t *Transport) Reader() io.Reader {
	return t.reader
}

// Writer returns the encrypted data writer associated with the transport.
func (t *Transport) Writer() io.Writer {
	return t.writer
}

// ResizeEvents exposes a stream of terminal resize notifications pushed by the
// remote peer. The channel is closed when the underlying connection shuts
// down. If the remote peer does not send resize events, the returned channel is
// nil.
func (t *Transport) ResizeEvents() <-chan WindowSize {
	return t.transport.resizeEvents()
}

// SendWindowSize pushes a terminal resize notification to the remote peer.
func (t *Transport) SendWindowSize(size WindowSize) error {
	return t.transport.sendWindowSize(size)
}

// Handshake establishes an encrypted AES-GCM transport on top of conn and
// performs password authentication. The same AES key and authentication
// password must be provided on both sides of the connection.
func Handshake(conn net.Conn, isServer bool, aesKey, authPassword string) (*Transport, error) {
	if aesKey == "" {
		return nil, errors.New("secureio: AES key must be provided")
	}
	if authPassword == "" {
		return nil, errors.New("secureio: authentication password must be provided")
	}

	serverNonce := make([]byte, 32)
	clientNonce := make([]byte, 32)

	if isServer {
		if _, err := rand.Read(serverNonce); err != nil {
			return nil, fmt.Errorf("secureio: generate server nonce: %w", err)
		}
		if _, err := conn.Write(serverNonce); err != nil {
			return nil, fmt.Errorf("secureio: send server nonce: %w", err)
		}
		if _, err := io.ReadFull(conn, clientNonce); err != nil {
			return nil, fmt.Errorf("secureio: read client nonce: %w", err)
		}
	} else {
		if _, err := io.ReadFull(conn, serverNonce); err != nil {
			return nil, fmt.Errorf("secureio: read server nonce: %w", err)
		}
		if _, err := rand.Read(clientNonce); err != nil {
			return nil, fmt.Errorf("secureio: generate client nonce: %w", err)
		}
		if _, err := conn.Write(clientNonce); err != nil {
			return nil, fmt.Errorf("secureio: send client nonce: %w", err)
		}
	}

	sessionKey := deriveSessionKey(aesKey, serverNonce, clientNonce)
	transport, err := newGCMTransport(conn, sessionKey)
	if err != nil {
		return nil, err
	}

	if !isServer {
		transport.enableResizeEvents()
	}

	expectedAuth := deriveAuthDigest(authPassword, serverNonce, clientNonce)

	if isServer {
		frameType, payload, err := transport.readFrame()
		if err != nil {
			return nil, fmt.Errorf("secureio: read auth frame: %w", err)
		}
		if frameType != frameTypeAuth {
			return nil, fmt.Errorf("secureio: unexpected frame type %d during authentication", frameType)
		}
		if subtle.ConstantTimeCompare(payload, expectedAuth[:]) != 1 {
			_ = transport.writeFrame(frameTypeAuthReject, nil)
			return nil, errors.New("secureio: authentication failed")
		}
		if err := transport.writeFrame(frameTypeAuthOK, nil); err != nil {
			return nil, fmt.Errorf("secureio: send auth acknowledgement: %w", err)
		}
	} else {
		if err := transport.writeFrame(frameTypeAuth, expectedAuth[:]); err != nil {
			return nil, fmt.Errorf("secureio: send auth frame: %w", err)
		}
		frameType, _, err := transport.readFrame()
		if err != nil {
			return nil, fmt.Errorf("secureio: read auth response: %w", err)
		}
		if frameType != frameTypeAuthOK {
			return nil, errors.New("secureio: authentication rejected by server")
		}
	}

	reader := &gcmReader{transport: transport}
	writer := &gcmWriter{transport: transport}
	return &Transport{transport: transport, reader: reader, writer: writer}, nil
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

	resizeCh   chan WindowSize
	resizeOnce sync.Once
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
			t.closeResizeEvents()
			return 0, err
		}
		switch frameType {
		case frameTypeData:
			if len(payload) == 0 {
				continue
			}
			t.readBuf = payload
		case frameTypeWindowSize:
			if err := t.handleWindowSize(payload); err != nil {
				t.closeResizeEvents()
				return 0, err
			}
			continue
		default:
			t.closeResizeEvents()
			return 0, fmt.Errorf("secureio: unexpected frame type %d while reading", frameType)
		}
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

func (t *gcmTransport) enableResizeEvents() {
	t.resizeCh = make(chan WindowSize, 1)
}

func (t *gcmTransport) resizeEvents() <-chan WindowSize {
	return t.resizeCh
}

func (t *gcmTransport) sendWindowSize(size WindowSize) error {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[0:], size.Rows)
	binary.BigEndian.PutUint16(payload[2:], size.Cols)
	return t.writeFrame(frameTypeWindowSize, payload)
}

func (t *gcmTransport) handleWindowSize(payload []byte) error {
	if len(payload) != 4 {
		return fmt.Errorf("secureio: invalid window size payload length %d", len(payload))
	}
	if t.resizeCh == nil {
		return nil
	}
	size := WindowSize{
		Rows: binary.BigEndian.Uint16(payload[0:2]),
		Cols: binary.BigEndian.Uint16(payload[2:4]),
	}

	select {
	case t.resizeCh <- size:
	default:
		select {
		case <-t.resizeCh:
		default:
		}
		select {
		case t.resizeCh <- size:
		default:
		}
	}
	return nil
}

func (t *gcmTransport) closeResizeEvents() {
	if t.resizeCh == nil {
		return
	}
	t.resizeOnce.Do(func() {
		close(t.resizeCh)
	})
}
