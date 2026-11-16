# psst

[![lint](https://github.com/evanpurkhiser/psst/actions/workflows/lint.yml/badge.svg)](https://github.com/evanpurkhiser/psst/actions/workflows/lint.yml)

`psst` (Private Short-lived Secret Transfer) gives local automation temporary,
selective access to a shared 1Password item.
A share link opens a five-minute session whose fields can be listed
before a caller retrieves a secret, downloads a file,
or uses a passkey in Chrome.

## Install

`psst` requires Linux with a systemd user manager and session D-Bus.

```console
cargo install --locked psst-cli
```

## Usage

Print the version-matched operational workflow before using psst:

```console
psst skill
```

The workflow covers the complete command sequence:

- `open` reads a public 1Password share link from standard input.
- `fields` lists selectors, field types, file metadata,
  and passkeys without secret values or private-key material.
- `get` writes one selected value to a pipe or redirected output.
- `download` verifies and decrypts one selected attachment.
- `passkey handoff` completes the matching request from the Chrome integration.
- `close` destroys the session immediately.

`get` and `download` refuse terminal output.
Sessions otherwise expire after five minutes,
and the daemon exits after five idle minutes.

## Chrome passkeys

The signed Chrome extension, native-messaging bridge,
and rootless-container mounts are described in
[Container browsers](docs/container-browsers.md).
The extension uses Chrome's Web Authentication proxy
so the passkey private key stays inside the psst daemon.

## Security model

The CLI starts a hardened transient `psst-daemon` service
and communicates with it through a mode-0600 Unix socket in `$XDG_RUNTIME_DIR`.
The daemon retains the encrypted item and derived item key for the session.
It decrypts item details only while servicing a request that needs them
and zeroizes sensitive buffers where practical.
Core dumps are disabled for both processes.

The session reference is a short-lived authorization capability.
It is printed by `open` and appears in later command arguments,
so it can be visible in local process listings and tool transcripts.
It should remain inside the current task.

These measures shorten plaintext lifetime
but do not defend against another process permitted to inspect the user's
memory.
Email-restricted shares are not supported.

See [Protocol details](docs/protocol.md) for the public-share key derivation,
attachment validation, and browser assertion boundaries.

## Development

```console
mise install
cargo test --locked --workspace --all-targets
prek run --all-files
```
