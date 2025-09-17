package secureio

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
)

// Handshake establishes a secure reader and writer on top of the provided
// connection using the requested cipher suite. The same passphrase must be
// supplied on both sides of the connection.
func Handshake(conn net.Conn, isServer bool, passphrase, cipherName string) (io.Reader, io.Writer, error) {
	suite, err := getCipherSuite(cipherName)
	if err != nil {
		return nil, nil, err
	}

	return suite.handshake(conn, isServer, passphrase)
}

type cipherSuite interface {
	handshake(conn net.Conn, isServer bool, passphrase string) (io.Reader, io.Writer, error)
	Name() string
}

var registeredSuites = map[string]cipherSuite{
	"aes": &aesSuite{},
	"xor": &xorSuite{},
}

func getCipherSuite(name string) (cipherSuite, error) {
	suite, ok := registeredSuites[name]
	if !ok {
		return nil, fmt.Errorf("secureio: unknown cipher suite %q", name)
	}
	return suite, nil
}

func deriveKey(passphrase string) []byte {
	sum := sha256.Sum256([]byte(passphrase))
	return sum[:]
}

func deriveBytes(direction string, serverNonce, clientNonce []byte, size int) []byte {
	h := sha256.New()
	h.Write([]byte(direction))
	h.Write(serverNonce)
	h.Write(clientNonce)
	sum := h.Sum(nil)
	if size <= len(sum) {
		return sum[:size]
	}

	buf := make([]byte, size)
	copy(buf, sum)
	pos := len(sum)
	for pos < size {
		h.Reset()
		h.Write(sum)
		sum = h.Sum(nil)
		n := copy(buf[pos:], sum)
		pos += n
	}
	return buf
}

const (
	directionServerToClient = "srv->cli"
	directionClientToServer = "cli->srv"
)

type aesSuite struct{}

func (s *aesSuite) Name() string { return "aes" }

func (s *aesSuite) handshake(conn net.Conn, isServer bool, passphrase string) (io.Reader, io.Writer, error) {
	key := deriveKey(passphrase)

	serverNonce := make([]byte, aes.BlockSize)
	clientNonce := make([]byte, aes.BlockSize)

	if isServer {
		if _, err := rand.Read(serverNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: failed to generate server nonce: %w", err)
		}
		if _, err := conn.Write(serverNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: failed to send server nonce: %w", err)
		}
		if _, err := io.ReadFull(conn, clientNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: failed to read client nonce: %w", err)
		}
	} else {
		if _, err := io.ReadFull(conn, serverNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: failed to read server nonce: %w", err)
		}
		if _, err := rand.Read(clientNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: failed to generate client nonce: %w", err)
		}
		if _, err := conn.Write(clientNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: failed to send client nonce: %w", err)
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("secureio: failed to create AES cipher: %w", err)
	}

	serverToClientIV := deriveBytes(directionServerToClient, serverNonce, clientNonce, aes.BlockSize)
	clientToServerIV := deriveBytes(directionClientToServer, serverNonce, clientNonce, aes.BlockSize)

	var readStream, writeStream cipher.Stream
	if isServer {
		readStream = cipher.NewCTR(block, clientToServerIV)
		writeStream = cipher.NewCTR(block, serverToClientIV)
	} else {
		readStream = cipher.NewCTR(block, serverToClientIV)
		writeStream = cipher.NewCTR(block, clientToServerIV)
	}

	reader := &cipher.StreamReader{S: readStream, R: conn}
	writer := &cipher.StreamWriter{S: writeStream, W: conn}

	return bufio.NewReader(reader), writer, nil
}

type xorSuite struct{}

func (s *xorSuite) Name() string { return "xor" }

func (s *xorSuite) handshake(conn net.Conn, isServer bool, passphrase string) (io.Reader, io.Writer, error) {
	key := deriveKey(passphrase)
	serverNonce := make([]byte, 16)
	clientNonce := make([]byte, 16)

	if isServer {
		if _, err := rand.Read(serverNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: failed to generate server nonce: %w", err)
		}
		if _, err := conn.Write(serverNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: failed to send server nonce: %w", err)
		}
		if _, err := io.ReadFull(conn, clientNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: failed to read client nonce: %w", err)
		}
	} else {
		if _, err := io.ReadFull(conn, serverNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: failed to read server nonce: %w", err)
		}
		if _, err := rand.Read(clientNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: failed to generate client nonce: %w", err)
		}
		if _, err := conn.Write(clientNonce); err != nil {
			return nil, nil, fmt.Errorf("secureio: failed to send client nonce: %w", err)
		}
	}

	serverToClientKey := mixKey(deriveBytes(directionServerToClient, serverNonce, clientNonce, len(key)), key)
	clientToServerKey := mixKey(deriveBytes(directionClientToServer, serverNonce, clientNonce, len(key)), key)

	var readKey, writeKey []byte
	if isServer {
		readKey = clientToServerKey
		writeKey = serverToClientKey
	} else {
		readKey = serverToClientKey
		writeKey = clientToServerKey
	}

	reader := &cipher.StreamReader{S: newXORStream(readKey), R: conn}
	writer := &cipher.StreamWriter{S: newXORStream(writeKey), W: conn}
	return bufio.NewReader(reader), writer, nil
}

type xorStream struct {
	key []byte
	pos int
}

func newXORStream(key []byte) cipher.Stream {
	if len(key) == 0 {
		panic("secureio: xor stream requires non-empty key")
	}
	copied := make([]byte, len(key))
	copy(copied, key)
	return &xorStream{key: copied}
}

func (x *xorStream) XORKeyStream(dst, src []byte) {
	if len(x.key) == 0 {
		panic("secureio: xor stream has empty key")
	}
	for i := range src {
		dst[i] = src[i] ^ x.key[x.pos%len(x.key)]
		x.pos++
	}
}

func mixKey(input, key []byte) []byte {
	if len(key) == 0 {
		panic("secureio: cannot mix with empty key")
	}
	if len(input) == 0 {
		return nil
	}
	result := make([]byte, len(input))
	copy(result, input)
	for i := range result {
		result[i] ^= key[i%len(key)]
	}
	return result
}

// ListCipherSuites returns the names of all registered cipher suites.
func ListCipherSuites() []string {
	names := make([]string, 0, len(registeredSuites))
	for name := range registeredSuites {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// RegisterCipherSuite allows external packages to register their own cipher suite
// implementations. It returns an error if the name is already in use.
func RegisterCipherSuite(name string, suite cipherSuite) error {
	if name == "" {
		return errors.New("secureio: cipher suite name cannot be empty")
	}
	if suite == nil {
		return errors.New("secureio: cipher suite cannot be nil")
	}
	if _, exists := registeredSuites[name]; exists {
		return fmt.Errorf("secureio: cipher suite %q already registered", name)
	}
	registeredSuites[name] = suite
	return nil
}
