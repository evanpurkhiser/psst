---
name: psst
description: Use PSST to receive an explicitly shared 1Password item, consume selected secrets without printing them, or authenticate with a shared passkey whose private key stays inside the PSST daemon.
---

# PSST

PSST turns a public 1Password item-sharing link into a short-lived local
session. The item remains encrypted in a hardened user daemon, and callers
request only the fields or passkey operations they need.

## Open and close every session

Give the share link to `open` on standard input. Never place it in a command
argument or print it:

```bash
session="$(printf '%s' "$share_url" | psst open)"
trap 'psst close "$session" 2>/dev/null || true' EXIT
```

The session expires after five minutes. A view-once share is consumed by
`open`, so use a short-lived multi-view share when the workflow may need a
retry. Close the session as soon as its consumer finishes:

```bash
psst close "$session"
trap - EXIT
```

## Consume a field

Inspect metadata first, then use an exact returned selector:

```bash
psst fields "$session"
psst get "$session" -- <selector> | <consumer>
psst download "$session" -- <file-selector> | <consumer>
```

`get` and `download` refuse terminal output. Keep the direct pipe intact; never
print, inspect, log, summarize, or save a returned value unless the user's task
explicitly requires a file. Retrieve only the fields required for the task.

## Authenticate with a passkey

The browser integration must already be installed. Trigger the site's normal
passkey action first, then arm the request that is waiting in PSST:

```bash
psst passkey describe "$session"
# Complete the identifier step or click the site's passkey button.
psst passkey arm "$session"
# Wait for that browser request to finish.
```

The browser holds an unarmed request for up to one minute. An arm binds to the
newest pending request, or to the next request when none is pending, and
authorizes one assertion for up to one minute. The browser sends the live
origin, challenge, relying-party ID, and credential allow list through Chrome
native messaging. The daemon validates them and returns the WebAuthn assertion;
neither the browser extension nor its caller receives the session identifier or
private key.

If the browser reports that PSST is unavailable or uses a native authenticator,
check the installed browser integration before arming again. Do not repeatedly
arm while probing the page: the matching assertion attempt consumes the arm,
including when its request fails validation.

`psst passkey assert` is the lower-level interface for a non-browser WebAuthn
consumer that already has the request's origin and challenge. Prefer the
browser integration for website authentication.

## Setup commands

Normal handoffs do not reinstall browser files. For initial setup:

```bash
psst browser install
```

Container browsers require an allowed peer UID and the mounts documented with
the installed PSST release. Setup changes are infrastructure work, separate
from consuming a shared item.
