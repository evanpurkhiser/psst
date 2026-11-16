---
name: psst
description: Use psst to receive an explicitly shared 1Password item, consume selected secrets without printing them, or authenticate with a shared passkey whose private key stays inside the psst daemon.
---

# psst

psst turns a public 1Password item-sharing link into a short-lived local
session.
The item remains encrypted in a hardened user daemon,
and callers request only the fields or passkey operations they need.

## Open and close every session

Give the share link to `open` on standard input.
Never place it in a command argument or print it.
Retain the returned opaque session reference for later tool calls:

```bash
printf '%s' "$share_url" | psst open
# Capture the single opaque line returned by the command.
```

If the command interface only provides live PTY input, start this command,
then send the share URL to its standard input:

```bash
IFS= read -rs share_url; printf '%s' "$share_url" | psst open
```

The silent `read` keeps the URL out of the command text and terminal echo.
Do not substitute the URL into the shell command.

Shell variables and traps do not persist across independent tool calls.
Pass the exact returned reference wherever `SESSION_REFERENCE` appears below;
it is a short-lived authorization capability
and necessarily appears in psst command arguments and local tool transcripts.
Do not publish or reuse it outside the current task.

The session expires after five minutes.
A view-once share is consumed by `open`,
so use a short-lived multi-view share when the workflow may need a retry.
Close the session as soon as its consumer finishes:

```bash
psst close SESSION_REFERENCE
```

## Inspect the item

Inspect metadata first, then use an exact returned selector:

```bash
psst fields SESSION_REFERENCE
psst get SESSION_REFERENCE -- SELECTOR | <consumer>
psst download SESSION_REFERENCE -- FILE_SELECTOR | <consumer>
```

`fields` also lists a shared passkey as `type: "passkey"` with its `rpId`
and `credentialId`.
Its presence confirms that the session can be used with the passkey commands
below.
The stored `credentialId` is metadata,
not the browser request ID used by `passkey handoff`.
Passkeys do not have a field selector and cannot be retrieved with `get`.

`get` and `download` refuse terminal output.
Keep the direct pipe intact; never print, inspect, log, summarize,
or save a returned value unless the user's task explicitly requires a file.
Retrieve only the fields required for the task.

## Authenticate with a passkey

The browser integration must already be installed.
Trigger the site's normal passkey action.
The browser displays **Waiting for psst** and **Continue without psst**.
Conditional mediation may display this prompt as soon as the login form loads.
Open and inspect the shared item before triggering the site's passkey action
when possible.
If the prompt or site transaction times out while waiting for the share,
reload the sign-in flow and trigger a new passkey request.
The prompt exposes a labeled browser request ID.
Hand off that exact request while the prompt waits:

```bash
# Complete the identifier step or click the site's passkey button.
psst passkey handoff SESSION_REFERENCE REQUEST_ID
# Success means psst produced the assertion for that browser request.
```

The extension starts Chrome's passkey request and waits
for the displayed request ID to be handed off.
`psst passkey handoff` waits for the browser to consume that authorization
and returns an error when assertion generation or validation fails.
Verify the site's resulting navigation or signed-in state
before closing the session.
Chrome supplies the live challenge, relying-party ID,
and credential allow list through its Web Authentication proxy.
The extension combines them with the live origin
and sends the assertion request through Chrome native messaging.
The daemon validates them and returns the WebAuthn assertion;
neither the browser extension nor its caller receives the session identifier
or private key.

**Continue without psst** cancels the psst wait
and uses Chrome's normal passkey flow.
If Chrome rejects the completed assertion,
trigger the site's passkey action again for a new request.
Each handoff is one-shot, including when its request fails WebAuthn validation.

## Setup commands

Normal handoffs do not reinstall browser files.
For initial setup:

```bash
psst browser install --peer-uid 65534
psst browser status
```

Rootless containers commonly appear as UID 65534 to the host.
If the browser reports a different rejected peer UID,
add that value with another `psst browser install --peer-uid UID` invocation.
`browser status` reports generated artifact presence and configured peers;
it does not probe Chrome or daemon connectivity.
Container browsers also require the mounts documented with the installed psst
release.
`psst browser reset` clears the container peer allowlist.
Setup changes are infrastructure work, separate from consuming a shared item.
