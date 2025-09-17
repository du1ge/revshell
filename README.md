# revshell

Simulate a fully interactive SSH-style shell terminal environment using Go to execute commands over an encrypted channel.

## Features

- Long-lived TCP connections between server and client.
- **Reverse** interactive shell: the server listens for inbound clients and, once connected, receives a full PTY-backed shell from the client machine.
- Fully interactive remote shell with history keys, readline support, and terminal control sequences.
- Pluggable stream encryption with selectable cipher suites (`aes`, `xor`) and the ability to register custom algorithms.
- Configurable prompt template, initial working directory, and shell executable provided by the client.

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

Launch the client on the machine you wish to control:

```bash
./client -addr 127.0.0.1:2222 -pass mysecret -cipher aes
```

Once the handshake completes, the server terminal is switched to raw mode and bridged directly to the client's shell. History keys (↑/↓), interactive programs, and terminal escape sequences now behave exactly like an SSH session. Use `exit` inside the remote shell to terminate the connection.

> **Note:** Because the remote shell runs on the client, only one interactive session can be active per server process.

### Prompt customization

The client accepts a `-prompt` flag allowing placeholders that are expanded before exporting `PS1` to the remote shell:

- `{{.USER}}` – expands to the shell escape `\u`.
- `{{.HOST}}` – expands to `\h`.
- `{{.CWD}}` – expands to `\w`.
- `{{.BASENAME}}` – expands to `\W`.

For example, to emulate the default bash prompt:

```bash
./client -pass mysecret -prompt "{{.USER}}@{{.HOST}} {{.BASENAME}}$ "
```

### Cipher suites

Two cipher suites are included:

- `aes` – AES-CTR mode with per-session nonces and independent streams for each direction.
- `xor` – lightweight XOR stream cipher derived from the shared secret (demonstrates how to plug in custom algorithms; use for testing only).

Additional ciphers can be registered at runtime using `secureio.RegisterCipherSuite`.

### Notes

- Both server and client must be launched with the same passphrase and cipher suite.
- The client can choose a different shell binary via `-shell` (defaults to `/bin/sh`) and initial working directory via `-workdir`.
- Keep the terminal window open on the server while the client is connected to maintain the long-lived session.
