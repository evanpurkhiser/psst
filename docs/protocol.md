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
