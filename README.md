# revshell

Simulate a fully interactive SSH-style shell terminal environment using Go to execute commands over an encrypted channel.

## Features

- Long-lived TCP connections between server and client.
- **Reverse** interactive shell: the server listens for inbound clients and, once connected, receives a full PTY-backed shell from the client machine.
- Fully interactive remote shell with history keys, readline support, and terminal control sequences.
- AES-GCM encrypted transport with explicit password authentication before a session is established.
- Configurable prompt template, initial working directory, and shell executable provided by the client.

## Building

```bash
go build ./cmd/server
go build ./cmd/client
```

## Usage

Start the server (listen on port 9999 by default):

```bash
./server --listen 0.0.0.0:9999 --aes-key <hex-encoded-key> --auth-password <shared-password>
```

Launch the client on the machine you wish to control:

```bash
./client --server 127.0.0.1:9999 --aes-key <hex-encoded-key> --auth-password <shared-password>
```

After a successful handshake the client detaches into the background on Linux systems, closes its standard file descriptors, and
continues streaming shell traffic to the server. Log messages are forwarded to the host syslog facility. Use the `--foreground`
flag to keep the process attached to the current terminal or when running on non-Linux platforms where daemonization is
unavailable.

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
./client --aes-key <hex-encoded-key> --auth-password <shared-password> --prompt "{{.USER}}@{{.HOST}} {{.BASENAME}}$ "
```

### Notes

- Both server and client must be launched with the same AES key and authentication password.
- The client can choose a different shell binary via `-shell` (defaults to `/bin/sh`) and initial working directory via `-workdir`.
- Specify `--foreground` to disable background mode and stream logs directly to the invoking terminal.
- Keep the terminal window open on the server while the client is connected to maintain the long-lived session.
