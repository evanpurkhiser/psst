# Container browsers

Chrome native-messaging hosts run in the browser's container. psst keeps its
session daemon on the host and exposes a separate socket that accepts WebAuthn
assertion requests only.
The daemon checks the connecting process UID
and never serves the normal session protocol on this socket.

Install `psst-browser-bridge` next to `psst`.
Repository and package builds can produce the static musl executable with:

```console
mise run build-browser-bridge
install -Dm755 target/x86_64-unknown-linux-musl/release/psst-browser-bridge ~/.cargo/bin/psst-browser-bridge
```

The build task selects the musl target for the current architecture
and prints the resulting executable path.
Package builds install the helper and signed Chrome extension as private files,
then set their absolute source paths when compiling the CLI:

```console
PSST_BROWSER_BRIDGE_PATH=/usr/lib/psst/browser-bridge \
PSST_BROWSER_EXTENSION_PATH=/usr/lib/psst/chrome-extension.crx \
  cargo build --release --locked
```

`psst integration install chrome` copies those files into the browser
integration directory.
Builds without configured paths resolve `psst-browser-bridge`
and `psst-chrome-extension.crx` next to the CLI.

Install the browser files and configure the UID that the host observes
for the container's browser process:

```console
psst integration install chrome --peer-uid 65534
```

Rootless user namespaces commonly appear as UID 65534 to the host process
that owns the socket.
Use the UID reported by `browser_peer_unauthorized`
when the runtime uses a different mapping.
Each `--peer-uid` adds to the existing allowlist;
repeat it to add several mappings in one command.

`psst integration status chrome` reports
whether each generated artifact is present and the current peer allowlist.
It does not probe Chrome, the daemon, or bridge connectivity.
`psst integration reset chrome` clears the peer allowlist without removing the
installed extension or native-host files.

Mount these host paths into the browser container:

| Host                                               | Container                                | Access    |
| -------------------------------------------------- | ---------------------------------------- | --------- |
| `~/.local/share/psst`                              | `/opt/psst`                              | read-only |
| `~/.local/share/psst/container-native-host`        | `/etc/opt/chrome/native-messaging-hosts` | read-only |
| `~/.local/share/psst/container-external-extension` | `/opt/google/chrome/extensions`          | read-only |
| `$XDG_RUNTIME_DIR/psst-browser`                    | `/run/psst`                              | read-only |

Create `$XDG_RUNTIME_DIR/psst-browser` with mode 0711
before starting the container.
The daemon creates `bridge.sock` there when a psst command starts it.
The socket is reachable through the explicit mount,
while the mode-0700 parent runtime directory keeps it unavailable to other host
users.

Branded Chrome reads the external-extension descriptor at startup
and installs the signed CRX from `/opt/psst/chrome-extension.crx` into its
profile.
No extension launch flag or developer mode is required.
The browser profile records the extension after the first startup
and accepts updated CRX versions signed by the same key.
