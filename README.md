# psst

[![lint](https://github.com/evanpurkhiser/psst/actions/workflows/lint.yml/badge.svg)](https://github.com/evanpurkhiser/psst/actions/workflows/lint.yml)

`psst` (Private Short-lived Secret Transfer) is a 1Password handoff tool
for coding agents and other local automation.
A human provides a public 1Password item-sharing link;
the agent can inspect its field names and types,
then explicitly retrieve only the values it needs.

## Install

`psst` requires Linux with a systemd user manager and session D-Bus.

```console
cargo install --locked psst-cli
```

## Agent workflow

Print the version-matched operational skill
before integrating psst into an agent or automation workflow:

```console
psst skill
```

Pass the share link on standard input, retain the returned session ID,
and arrange cleanup immediately:

```console
$ set -euo pipefail
$ session="$(printf '%s' "$ONEPASSWORD_SHARE_URL" | psst open)"
$ trap 'psst close "$session" 2>/dev/null || true' EXIT
$ psst fields "$session"
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
$ psst get "$session" -- password | command-that-reads-a-secret-from-stdin
$ psst download "$session" -- receipt | command-that-reads-a-pdf
$ psst close "$session"
$ trap - EXIT
```

Agents should call `fields` first, use an exact returned `selector`,
retrieve only required values,
and close the session as soon as the consumer finishes.
The `--` before a selector keeps names beginning with `-` from becoming options.
Prefer a view-once share.
`open` consumes it once,
then the daemon serves the session from memory for up to five minutes.
Losing the session ID or allowing the session to expire may make the item
unrecoverable; use a short-lived multi-view share when retrieval must be
retryable.
The session ID is a short-lived authorization capability rather than decrypted
secret material.
It is printed by `open` and passed in later command arguments,
so local process listings and tool transcripts may contain it.
Do not publish or reuse it outside the current task.
`close` destroys only the local session.
Revoke an active multi-view link from the item's Sharing History in 1Password.

For command interfaces that only provide a live PTY,
start a silent shell read
and then send the share URL through the running process's standard input:

```console
IFS= read -rs share_url; printf '%s' "$share_url" | psst open
```

This keeps the share URL out of the command text and terminal echo.

`fields` returns an ordered JSON array containing available field
and passkey metadata.
Normal fields contain `selector`, `label`, and `type`.
File fields also contain `filename` and their decrypted byte `size`:

```json
{
  "selector": "receipt",
  "label": "receipt",
  "type": "file",
  "filename": "receipt.pdf",
  "size": 116736
}
```

A shared passkey appears after the normal fields:

```json
{
  "type": "passkey",
  "credentialId": "Y3JlZGVudGlhbA",
  "rpId": "example.com"
}
```

Passkeys do not have a field selector and are used through `psst passkey`.
The stored `credentialId` is not the browser request ID used by `handoff`.

Selectors are unique and stable for the session;
duplicate names receive numeric suffixes.
Consumers should ignore additional object keys added by a future release.

`get` writes strings as raw bytes without a trailing newline
and writes other values as JSON.
TOTP fields return the current code.
Credit-card expiration fields return `MM/YYYY`.
File values are available only through `download`,
which verifies and decrypts the attachment before writing its original bytes.
Attachments are currently limited to 64 MiB.

### Agent Browser credentials

Install psst as an Agent Browser credential provider:

```console
psst integration install agent-browser
```

The installer honors `AGENT_BROWSER_CONFIG` and accepts `--config PATH`.

Then fill an existing login form without putting username
or password in shell variables, files, or command arguments:

```console
agent-browser --session work auth login sentry \
  --credential-provider psst --item SESSION_REFERENCE \
  --url https://identity.example.com/login --no-navigate
```

The item must expose `username` and `password` selectors.
Agent Browser receives them over the plugin's standard-I/O protocol
and keeps them out of normal command output.

## Passkeys

psst can complete a browser passkey request without exporting its private key.
The daemon decrypts and uses the key only
while producing the requested WebAuthn assertion.
Chrome's Web Authentication proxy converts
that assertion into the native credential returned to the website.

### Browser setup

The browser integration is distributed as a signed CRX
and installed through Chrome's external-extension mechanism.
Configure the browser bridge and the host UID observed
for the rootless container:

```console
psst integration install chrome --peer-uid 65534
```

Use the UID reported by `browser_peer_unauthorized`
when the container has a different user mapping.
Mount the generated integration paths
as described in [Container browsers](docs/container-browsers.md).

Open the 1Password share and trigger the site's passkey action.
The extension shows **Use psst** and **Continue with browser**.
The prompt exposes a labeled browser request ID before either choice.
Record it, choose **Use psst**, then pass it to `handoff`:

```console
$ printf '%s' "$ONEPASSWORD_SHARE_URL" | psst open
OPAQUE_SESSION_REFERENCE
$ agent-browser --session work open https://login.example.com
# Complete the site's identifier steps and trigger its passkey action.
# Click "Use psst" and read its browser request ID.
$ psst passkey handoff OPAQUE_SESSION_REFERENCE REQUEST_ID
# Success means psst produced the assertion for that browser request.
$ psst close OPAQUE_SESSION_REFERENCE
```

**Continue with browser** immediately passes the original request to Chrome.
**Use psst** starts a handoff for that exact request;
no native host or daemon request is created before that choice.
A handoff authorizes its displayed identifier once,
waits for the browser to consume it, and expires after one minute.
Equivalent concurrent requests from the page share the same choice
and assertion.
Each Chrome instance presents one request choice at a time.
Independent browser instances can complete distinct handoffs concurrently.
The extension never receives the psst session reference or private key.
Conditional mediation requests surface the same choice before form submission.
Open the share first when possible; if the prompt or site transaction expires,
reload the sign-in flow and trigger a new passkey request.
Silent mediation remains with Chrome because it cannot require user interaction.

Use `psst integration status chrome` to inspect generated artifact presence
and the container peer allowlist.
It does not probe Chrome, the daemon, or bridge connectivity.
`psst integration reset chrome` clears the peer allowlist without removing the
installed browser assets.

### Low-level assertions

`psst passkey describe` returns the credential's relying-party
and credential identifiers.
`psst passkey assert` accepts a JSON WebAuthn request on standard input
and writes its assertion as JSON.
These commands are intended for a non-browser WebAuthn consumer
that already owns the request origin and challenge.
The daemon rejects origins outside the stored relying party,
mismatched relying-party IDs, and allow lists that exclude the credential.

## Output safety

`open` accepts a share URL only on standard input,
so `psst` never puts it in its own argument list.
The producing command and its logs must also keep the URL private.
`open` refuses terminal input.

`get` and `download` refuse terminal output
before asking the daemon to decrypt a value:

```text
error secret_to_terminal: refusing to write a secret to a terminal; pipe or redirect stdout
```

Prefer a direct pipe to the consuming process.
A terminal check cannot distinguish an intended consumer from a process
that captures piped output,
and a redirected file uses the caller's permissions and umask.

Errors go to stderr with a stable code and human-readable message.
This includes command-line usage errors and safety refusals:

```console
$ psst fields expired-session
error session_not_found: session "expired-session" was not found or has expired
$ psst get expired-session password
error secret_to_terminal: refusing to write a secret to a terminal; pipe or redirect stdout
```

Exit statuses group failures by action: `10` for input, `11` for share access,
`12` for protocol or decryption, `20` for fields, `21` for unsafe output,
`22` for sessions, and `30` for local runtime failures.

## Session and security model

The first command asks the systemd user manager over D-Bus to start a hardened
transient `psst-daemon` service.
The CLI communicates with it through a mode-0600 Unix socket in
`$XDG_RUNTIME_DIR`.
Sessions use opaque random identifiers, expire five minutes after `open`,
and can be destroyed earlier with `close`.
The daemon exits after five idle minutes
and has a one-hour systemd runtime limit.

The daemon retains the encrypted item and its derived AES key.
It decrypts item details only while servicing a request that needs them.
Passkey operations also decrypt the overview for relying-party metadata.
Sensitive buffers managed by `psst` are zeroized where practical when dropped.
Core dumps are disabled for the CLI and daemon.
These measures shorten plaintext lifetime
but do not defend against another process permitted to inspect the user's
memory.

Email-restricted shares are not supported.
See [Protocol details](docs/protocol.md) for the public-share key derivation
and encrypted container format.

## Development

```console
mise install
cargo test --locked --all-targets
prek run --all-files
```
