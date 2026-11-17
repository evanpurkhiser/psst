# Container browsers

The signed Chrome extension communicates with the host's narrow browser HTTP
interface.
It can register, wait for, and cancel WebAuthn requests.
It cannot list sessions or retrieve fields, TOTP values, or attachments.

Install the packaged extension files:

```console
psst browser install
```

`psst browser status` reports whether the CRX
and external-extension descriptor are present.
It does not probe Chrome or daemon connectivity.

Mount these host paths into the browser container:

| Host                                               | Container                       | Access    |
| -------------------------------------------------- | ------------------------------- | --------- |
| `~/.local/share/psst`                              | `/opt/psst`                     | read-only |
| `~/.local/share/psst/container-external-extension` | `/opt/google/chrome/extensions` | read-only |

Branded Chrome reads the external-extension descriptor at startup
and installs `/opt/psst/chrome-extension.crx` into its persistent profile.
The profile accepts updated CRX versions signed by the same key.

The extension connects to:

```text
http://host.containers.internal:7338
```

The service defaults to a loopback-only browser listener.
Configure pasta to map Podman's `host.containers.internal` address to host
loopback:

```ini
Network=pasta:--map-host-loopback=169.254.1.2
```

Podman provides `169.254.1.2`
as `host.containers.internal` inside the container.
This keeps the listener off the host's LAN, WAN, and tailnet addresses.

The extension supplies a public request UUID and receives an independent,
unguessable capability.
It presents that capability in an authorization header while long-polling
for the result.
CORS permits only the packaged extension origin.
