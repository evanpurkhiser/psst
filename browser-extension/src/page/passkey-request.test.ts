import {describe, expect, it} from 'vitest';

import {serializePasskeyRequest} from './passkey-request';

describe('passkey request serialization', () => {
  it('encodes WebAuthn buffers as unpadded base64url', () => {
    const request = serializePasskeyRequest({
      challenge: new Uint8Array([251, 255]),
      rpId: 'example.com',
      allowCredentials: [{id: new Uint8Array([255, 239]), type: 'public-key'}],
    });

    expect(request).toEqual({
      challenge: '-_8',
      rpId: 'example.com',
      allowCredentials: ['_-8'],
    });
  });
});
