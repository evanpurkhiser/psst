# psst

[![lint](https://github.com/evanpurkhiser/psst/actions/workflows/lint.yml/badge.svg)](https://github.com/evanpurkhiser/psst/actions/workflows/lint.yml)

`psst` gives local automation temporary access to a shared 1Password item.
A share link becomes a five-minute session.
During that session, a caller can inspect safe metadata,
retrieve a specific field, download an attachment, or use a passkey in Chrome.

Secret values are written directly to their consumer instead of the terminal.
Passkey private keys stay inside the psst service.

## Installation

psst runs on Linux with systemd and a system D-Bus.
On Arch Linux, install the
[`psst` AUR package](https://aur.archlinux.org/packages/psst), then start the
service and install the Chrome integration for the current user:

```console
sudo systemctl enable --now psst.service
psst browser install
```

The package includes the CLI, system service, D-Bus policy,
dedicated `_psst` account, and signed Chrome extension.

## Usage

Start by checking for an active session.
A session may already have been shared through another client:

```console
psst sessions
```

If the expected item is missing, wait for the user to share it:

```console
psst sessions --live
```

The command writes the active sessions and each newly created session
as one line of JSON, then continues waiting.
It runs until `Ctrl-C`; stop it after the expected title or domain appears.

To open a share link directly,
pass it on standard input so it does not appear in the command line:

```console
printf '%s' "$share_url" | psst open
```

The command returns an opaque session ID.
Use it to inspect the item before requesting a value:

```console
psst fields SESSION_ID
psst get SESSION_ID -- SELECTOR | consumer
psst download SESSION_ID -- FILE_SELECTOR | consumer
psst close SESSION_ID
```

`get` and `download` refuse terminal output.
Sessions expire after five minutes and can be closed sooner.

For the complete, version-matched operational workflow, run:

```console
psst skill
```

## Chrome passkeys

When a site requests a passkey,
the Chrome extension displays a request ID and waits for psst.
Complete that request with the session containing the matching passkey:

```console
psst passkey handoff SESSION_ID REQUEST_ID
```

The extension receives the signed WebAuthn assertion.
The session ID and private key remain in the service.

The signed extension and rootless-container connection are described in
[Container browsers](docs/container-browsers.md).

## Security model

The `psst.service` system unit runs the daemon as the dedicated,
unprivileged `_psst` account.
The CLI communicates with it through a system D-Bus interface restricted to Unix
user `evan`.
The daemon retains the encrypted item and derived item key for the session.
It decrypts item details only while servicing a request that needs them
and zeroizes sensitive buffers where practical.
Core dumps are disabled for the service and CLI.

The session reference is an opaque identifier.
D-Bus authorization is the local security boundary;
processes already running as `evan` are trusted.

The create-only sharing listener accepts a JSON share URL
and is intended to sit behind tailnet-restricted nginx.
The separate browser listener can register and complete WebAuthn requests
but cannot enumerate sessions or retrieve fields.

These measures shorten plaintext lifetime
but do not defend against another process permitted to inspect the user's
memory.
Email-restricted shares are not supported.

See [Protocol details](docs/protocol.md) for the public-share key derivation,
attachment validation, and browser assertion boundaries.

## Development

`cargo install` builds the CLI without the system service, D-Bus policy,
service account, or Chrome extension.
Use it for development only.

```console
mise install
cargo test --locked --workspace --all-targets
prek run --all-files
```
