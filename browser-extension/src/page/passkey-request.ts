import type {PasskeyRequest} from '../protocol';

const encode = (value: BufferSource) => {
  const bytes = ArrayBuffer.isView(value)
    ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
    : new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
};

/**
 * Serializes the fields psst must bind to a WebAuthn assertion.
 */
export const serializePasskeyRequest = (
  options: PublicKeyCredentialRequestOptions,
): PasskeyRequest => ({
  challenge: encode(options.challenge),
  rpId: options.rpId ?? location.hostname,
  allowCredentials: (options.allowCredentials ?? []).map(item => encode(item.id)),
});
