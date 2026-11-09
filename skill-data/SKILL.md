---
name: psst
description: Use psst to receive an explicitly shared 1Password item, consume selected secrets without printing them, or authenticate with a shared passkey whose private key stays inside the psst daemon.
---

# psst

psst turns a public 1Password item-sharing link into a short-lived local
session. The item remains encrypted in a hardened user daemon, and callers
request only the fields or passkey operations they need.

## Open and close every session

Give the share link to `open` on standard input. Never place it in a command
argument or print it. Retain the returned opaque session reference for later
tool calls:

```bash
printf '%s' "$share_url" | psst open
# Capture the single opaque line returned by the command.
```

Shell variables and traps do not persist across independent tool calls. Pass the
exact returned reference wherever `SESSION_REFERENCE` appears below; never echo
or log it.

The session expires after five minutes. A view-once share is consumed by
`open`, so use a short-lived multi-view share when the workflow may need a
retry. Close the session as soon as its consumer finishes:

```bash
psst close SESSION_REFERENCE
```

## Consume a field

Inspect metadata first, then use an exact returned selector:

```bash
psst fields SESSION_REFERENCE
psst get SESSION_REFERENCE -- SELECTOR | <consumer>
psst download SESSION_REFERENCE -- FILE_SELECTOR | <consumer>
```

`get` and `download` refuse terminal output. Keep the direct pipe intact; never
print, inspect, log, summarize, or save a returned value unless the user's task
explicitly requires a file. Retrieve only the fields required for the task.

## Authenticate with a passkey

The browser integration must already be installed. Trigger the site's normal
passkey action. The browser displays **Use psst** and **Continue with browser**.
Conditional mediation may display this choice as soon as the login form loads.
If the passkey has not been shared, ask Evan to share the matching 1Password
item before choosing **Use psst**; the original browser request remains pending.
Choose **Use psst**, read the request identifier from its status, and hand off
that exact request:

```bash
# Complete the identifier step or click the site's passkey button.
psst passkey handoff SESSION_REFERENCE REQUEST_ID
# The existing browser request finishes without a retry.
```

**Continue with browser** immediately uses Chrome's normal passkey flow. **Use
psst** creates a request identifier and starts waiting for the CLI handoff.
`psst passkey handoff` authorizes that identifier for one minute. The browser
sends the live origin, challenge, relying-party ID, and credential allow list
through Chrome native messaging only after the browser choice. The daemon
validates them and returns the WebAuthn assertion; neither the browser extension
nor its caller receives the session identifier or private key.

If the handoff fails, the browser keeps **Continue with browser** available and
offers a new psst request identifier for another attempt. Each handoff is
one-shot, including when its request fails WebAuthn validation.

`psst passkey assert` is the lower-level interface for a non-browser WebAuthn
consumer that already has the request's origin and challenge. Prefer the
browser integration for website authentication.

## Setup commands

Normal handoffs do not reinstall browser files. For initial setup:

```bash
psst browser install
psst browser status
```

Container browsers require an allowed peer UID and the mounts documented with
the installed psst release. `psst browser reset` clears the container peer
allowlist. Setup changes are infrastructure work, separate from consuming a
shared item.
