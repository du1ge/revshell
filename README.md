# revshell

Simulate a fully interactive SSH-style shell terminal environment using Go to execute commands over an encrypted channel.

## Features

- Long-lived TCP connections between server and client.
- Interactive remote shell that supports running arbitrary commands, `cd`, and exiting with `exit`.
- Pluggable stream encryption with selectable cipher suites (`aes`, `xor`) and the ability to register custom algorithms.
- Configurable prompt template, initial working directory, and shell executable.

## Building

```bash
go build ./cmd/server
go build ./cmd/client
```

## Usage

Start the server (listen on port 2222 by default):

```bash
./server -pass mysecret -listen 0.0.0.0:2222 -cipher aes
```

Connect with the client:

```bash
./client -addr 127.0.0.1:2222 -pass mysecret -cipher aes
```

Once connected you are greeted with a prompt similar to `user@host /current/path$`. Type commands exactly as you would in an SSH session. Use `exit` to terminate the session.

### Prompt customization

The server accepts a `-prompt` flag allowing placeholders that are expanded on every command:

- `{{.USER}}` – current user name as seen by the server.
- `{{.HOST}}` – host name of the server machine.
- `{{.CWD}}` – absolute path of the current working directory.
- `{{.BASENAME}}` – basename of the current working directory.

For example:

```bash
./server -pass mysecret -prompt "[{{.BASENAME}}]$ "
```

### Cipher suites

Two cipher suites are included:

- `aes` – AES-CTR mode with per-session nonces and independent streams for each direction.
- `xor` – lightweight XOR stream cipher derived from the shared secret (demonstrates how to plug in custom algorithms; use for testing only).

Additional ciphers can be registered at runtime using `secureio.RegisterCipherSuite`.

### Notes

- Both server and client must be launched with the same passphrase and cipher suite.
- The `-shell` flag allows switching to shells such as `/bin/bash` if available.
- Keep the terminal window open while the client is connected to maintain the long-lived session.
