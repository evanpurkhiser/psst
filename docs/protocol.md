# Public-share protocol

`psst` implements 1Password's public item-sharing protocol directly. 1Password
documents its high-level design in the
[1Password security design](https://agilebits.github.io/security-design/share.html).
The wire-level details are not a versioned public API, so `psst` validates
container algorithms and content types before decryption and fails closed when
they change.

## Key derivation

A share URL fragment is a base64url-encoded 32-byte secret. The fragment stays
on the recipient and is never included in an HTTP request.

The client derives three values with HKDF-SHA256, an empty salt, and distinct
`info` values:

| Purpose | `info` | Length | Encoding |
| --- | --- | ---: | --- |
| Record locator | `share_item_uuid` | 16 bytes | lowercase Base32, no padding |
| Retrieval token | `share_item_token` | 16 bytes | lowercase Base32, no padding |
| Item key | `share_item_encryption_key` | 32 bytes | raw bytes |

## Retrieval and decryption

The client requests `/api/v1/share/{uuid}` from `share.1password.com` with the
retrieval token in the `OP-Share-Token` header. The response contains
`encOverview` and `encDetails` containers.

Both containers use AES-256-GCM with a 12-byte IV. The authentication tag is
appended to the ciphertext in the container's base64url `data` member. The
decrypted payload is UTF-8 JSON. `fields` exposes metadata for populated fields
from the details payload; it does not include their values.

## Attachments

File fields contain a document ID, filename, byte sizes, SHA-256 integrity hash,
AES-256-GCM key, and 12-byte nonce. The share response provides a temporary file
download token. The client sends that token in `OP-File-Download-Token` to
`/api/v1/file/{share_uuid}/{document_id}` and receives a signed HTTPS URL on a
1Password file host.

The downloaded bytes contain the ciphertext followed by the 16-byte GCM tag.
Before decryption, `psst` verifies their size and SHA-256 hash against the file
field. It then authenticates and decrypts the bytes and verifies the plaintext
size. The daemon sends a JSON response header followed by the exact binary
payload over its Unix socket, avoiding base64 expansion and preserving arbitrary
file contents.

## Passkey assertions

1Password stores passkey metadata in the encrypted overview and its user handle
and P-256 private key in the encrypted details. Shared items encode it as a hex
scalar or a base64url-wrapped JSON Web Key; PSST normalizes both inside the
daemon.

`passkey describe` returns only the relying-party ID, credential ID, and
credential type. For `passkey assert`, the daemon validates the requested HTTPS
origin against the stored relying-party ID, confirms the optional relying-party
ID and credential allow list, and creates `clientDataJSON` and authenticator
data. It signs the authenticator data and SHA-256 client-data hash with ES256 and
returns a WebAuthn assertion. The assertion uses a zero signature counter, as
the authenticator's indication that it does not support a coordinated signature
counter.

The private key exists only in the daemon's decrypted request buffers and P-256
signing object. The daemon protocol has no response variant for private-key
material and offers no arbitrary-byte signing operation.

## Browser bridge

The Chrome extension forwards the top-level page origin, challenge,
relying-party ID, and credential allow list through Chrome native messaging.
The native host keeps an unarmed request pending for up to one minute.
`passkey arm` binds an active session to the newest pending request, or to the
next request when none is pending, and expires after one minute. The matching
request consumes the arm even when its WebAuthn validation fails. Equivalent
concurrent calls are coalesced into one assertion, which the extension returns
to each caller.

The Agent Browser plugin implements its existing `launch.mutate` capability and
returns the installed extension directory for local Chrome launches. It does
not participate in assertion signing.

Container browsers use a second Unix socket that accepts assertion requests
only. The daemon verifies the connecting process UID against the configured
peer list before reading a request. The main mode-0600 session socket remains
outside the container. A small native-messaging proxy converts Chrome's framed
standard-I/O messages to newline-delimited messages on the restricted socket.
