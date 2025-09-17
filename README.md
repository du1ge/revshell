# revshell

Simulate a fully interactive SSH-style shell terminal environment using Go to execute commands over an encrypted channel.

## Features

- Long-lived TCP connections between server and client.
- Fully interactive remote shell backed by a pseudo-terminal on the client so history, tab-completion, and job control work as expected.
- Pluggable stream encryption with selectable cipher suites (`aes`, `xor`) and the ability to register custom algorithms.
- Configurable prompt template, initial working directory, and shell executable.

## Building

```bash
go build ./cmd/server
go build ./cmd/client
```

## Usage

Start the server on the machine that will control remote clients (listen on port 2222 by default):

```bash
./server -pass mysecret -listen 0.0.0.0:2222 -cipher aes
```

Run the client on the machine you want to control:

```bash
./client -addr 127.0.0.1:2222 -pass mysecret -cipher aes
```

Once connected the server terminal becomes an interactive shell attached to the client. Type commands exactly as you would in an SSH session (arrow keys, tab-completion, and Ctrl+C work). Use `exit` to terminate the session.

### Prompt customization

The server accepts a `-prompt` flag allowing placeholders that are expanded on the client shell:

- `{{.USER}}` – current user name on the client machine.
- `{{.HOST}}` – host name of the client machine.
- `{{.CWD}}` – absolute path of the current working directory (maps to `\w`).
- `{{.BASENAME}}` – basename of the current working directory (maps to `\W`).

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
- The `-shell` flag allows switching to shells such as `/bin/bash` if available (the executable is resolved on the client).
- Keep the terminal window open on the server while a client is connected so you remain attached to the remote shell.
- The server handles one interactive session at a time; wait for a session to close before accepting the next connection.
