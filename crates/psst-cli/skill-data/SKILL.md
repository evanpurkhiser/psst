---
name: psst
description: Use psst to access a user-shared 1Password item or complete a browser passkey handoff without exposing secrets.
---

# psst

psst makes a shared 1Password item available as a five-minute local session.
Retrieve only the fields needed for the task, and close the session when done.

## Find a session

Check for the expected item by title and domain:

```bash
psst sessions
```

If it is missing, start the live list before asking the user to share it:

```bash
psst sessions --live
```

Keep the command running while the user shares the item with psst.
Do not ask them to paste a share URL into the conversation.
The command emits active and newly created sessions as JSON Lines.
Stop it with `Ctrl-C` when the expected item appears, then use its exact `id`.

## Inspect and retrieve

List safe metadata before retrieving a value:

```bash
psst fields SESSION_ID
```

Use an exact selector from the response
and pipe the value directly to its consumer:

```bash
psst get SESSION_ID -- SELECTOR | consumer
psst download SESSION_ID -- FILE_SELECTOR | consumer
```

Never print, inspect, log, summarize,
or save a returned value unless the task explicitly requires a file.
`get` and `download` refuse terminal output.

For a username and password login, pass the session directly to agent-browser:

```bash
agent-browser --session BROWSER_SESSION auth login LOGIN_NAME \
  --credential-provider psst --item SESSION_ID \
  --url https://identity.example.com/login --no-navigate
```

## Use a passkey

Confirm that `fields` lists a passkey with the expected `rpId`,
then trigger the site's passkey flow.
The browser prompt displays a request ID while it waits for psst:

```bash
psst passkey handoff SESSION_ID REQUEST_ID
```

Verify that the site completed authentication.
A handoff is one-shot; trigger a new browser request before retrying a failed
or expired handoff.

## Open a link directly

When a share link is already available through a secure handoff:

```bash
printf '%s' "$share_url" | psst open
```

Never put the literal link in a command argument, tool call, log,
or conversation.
Use the returned session ID with the commands above.

## Close the session

```bash
psst close SESSION_ID
```
