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

`psst browser install` copies those files into the browser integration
directory.
Builds without configured paths resolve `psst-browser-bridge`
and `psst-chrome-extension.crx` next to the CLI.

Install the browser files:

```console
psst browser install
```

`psst browser status` reports whether each generated artifact is present.
It does not probe Chrome, the daemon, or bridge connectivity.

Mount these host paths into the browser container:

| Host                                               | Container                                | Access    |
| -------------------------------------------------- | ---------------------------------------- | --------- |
| `~/.local/share/psst`                              | `/opt/psst`                              | read-only |
| `~/.local/share/psst/container-native-host`        | `/etc/opt/chrome/native-messaging-hosts` | read-only |
| `~/.local/share/psst/container-external-extension` | `/opt/google/chrome/extensions`          | read-only |
| `$XDG_RUNTIME_DIR/psst-browser`                    | `/run/psst`                              | read-only |

Create `$XDG_RUNTIME_DIR/psst-browser` with mode 0700
before starting the container.
The daemon creates `bridge.sock` there when a psst command starts it.
The container browser user must have read and write access to the socket.

Branded Chrome reads the external-extension descriptor at startup
and installs the signed CRX from `/opt/psst/chrome-extension.crx` into its
profile.
No extension launch flag or developer mode is required.
The browser profile records the extension after the first startup
and accepts updated CRX versions signed by the same key.
