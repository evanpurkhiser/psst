# Container browsers

Chrome native-messaging hosts run in the browser's container. psst keeps its
session daemon on the host and exposes a separate socket that accepts WebAuthn
assertion requests only. The daemon checks the connecting process UID and never
serves the normal session protocol on this socket.

Install the browser files and configure the UID that the host observes for the
container's browser process:

```console
$ psst browser install --peer-uid 65534
/home/you/.local/share/psst/chrome-extension
```

Rootless user namespaces commonly appear as UID 65534 to the host process that
owns the socket. Use the UID reported by `browser_peer_unauthorized` when the
runtime uses a different mapping. Repeat `--peer-uid` to allow more than one
mapping.

`psst browser status` reports the installed paths and current peer allowlist.
`psst browser reset` clears the peer allowlist without removing the installed
extension or native-host files.

Mount these host paths into the browser container:

| Host | Container | Access |
| --- | --- | --- |
| `~/.local/share/psst` | `/opt/psst` | read-only |
| `~/.local/share/psst/container-native-host` | `/etc/opt/chrome_for_testing/native-messaging-hosts` | read-only |
| `$XDG_RUNTIME_DIR/psst-browser` | `/run/psst` | read-only |

Create `$XDG_RUNTIME_DIR/psst-browser` with mode 0711 before starting the
container. The daemon creates `bridge.sock` there when a psst command starts it.
The socket is reachable through the explicit mount, while the mode-0700 parent
runtime directory keeps it unavailable to other host users.

Start Chrome for Testing with:

```text
--load-extension=/opt/psst/chrome-extension
```

Recent branded Chrome builds ignore unpacked-extension launch flags. Chrome for
Testing supports the flag and uses the native-host directory shown above.
Pre-existing CDP sessions need no Agent Browser plugin because the container
loads the extension when Chrome starts.
