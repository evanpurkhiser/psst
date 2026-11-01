# psst

[![lint](https://github.com/evanpurkhiser/psst/actions/workflows/lint.yml/badge.svg)](https://github.com/evanpurkhiser/psst/actions/workflows/lint.yml)

`psst`—Private Short-lived Secret Transfer—turns a public 1Password
item-sharing link into a short-lived local session. It lets automation inspect
an item's field structure before explicitly requesting a value.

```console
$ printf '%s' "$ONEPASSWORD_SHARE_URL" | psst open
o4d2l7sc6q3fcq2h

$ psst fields o4d2l7sc6q3fcq2h
[
  {
    "selector": "username",
    "label": "username",
    "type": "string"
  },
  {
    "selector": "password",
    "label": "password",
    "type": "concealed"
  }
]

$ psst get o4d2l7sc6q3fcq2h password > /path/to/consumer
$ psst close o4d2l7sc6q3fcq2h
```

Share URLs are read from standard input so the capability does not appear in
the process argument list. Field values are written only by `get`; callers
must redirect or pipe them. `get` checks stdout before contacting the daemon
and refuses to decrypt a value when stdout is a terminal:

```text
psst: refusing to write a secret to a terminal; pipe or redirect stdout
```

This check distinguishes terminals from pipes and files. It cannot distinguish
a legitimate pipe consumer from a process that captures piped output.

## Session model

The first command starts a transient user service and communicates with it over
a Unix socket in `$XDG_RUNTIME_DIR`. The socket is mode 0600. Each session has
an opaque random identifier and expires five minutes after it is opened.
`close` drops it immediately. The daemon exits after five idle minutes and has
a one-hour systemd runtime limit as a final fail-safe.

The transient service disables core dumps, prevents privilege escalation, uses
a private temporary directory, and applies a mode-077 process umask.

The daemon stores the encrypted item and its derived AES key. Plaintext exists
only while handling `fields` or `get`. Plaintext buffers, derived keys, share
tokens, request buffers, and selected values are zeroized when dropped. This
reduces their lifetime; it does not defend against a process with permission to
inspect this process's memory.

Retrieving a view-once share consumes its view when `open` downloads it.
Email-restricted shares are not supported yet.

## Public-share decryption

1Password documents the high-level protocol in its
[security design](https://agilebits.github.io/security-design/share.html). A
share URL fragment is a base64url-encoded 32-byte secret. The fragment stays on
the recipient and is never included in an HTTP request.

The current public client derives three values with HKDF-SHA256, an empty salt,
and distinct `info` values:

| Purpose | `info` | Length | Encoding |
| --- | --- | ---: | --- |
| Record locator | `share_item_uuid` | 16 bytes | lowercase Base32, no padding |
| Retrieval token | `share_item_token` | 16 bytes | lowercase Base32, no padding |
| Item key | `share_item_encryption_key` | 32 bytes | raw bytes |

The client requests `/api/v1/share/{uuid}` with the retrieval token in the
`OP-Share-Token` header. The response contains `encOverview` and `encDetails`
containers. Both use AES-256-GCM with a 12-byte IV; the authentication tag is
appended to the ciphertext in the container's base64url `data` member. The
decrypted payload is UTF-8 JSON. Only populated fields from the details payload
are exposed by `fields`.

These wire-level details are not a versioned public API. Container algorithms
and content types are validated before decryption so a protocol change fails
closed instead of producing a plausible but incorrect value.

## Development

```console
$ mise install
$ cargo test --all-targets
$ prek run --all-files
```
