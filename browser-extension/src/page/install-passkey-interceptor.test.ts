// @vitest-environment happy-dom

import {afterEach, describe, expect, it, vi} from 'vitest';

import {installPasskeyInterceptor} from './install-passkey-interceptor';

afterEach(() => {
  Reflect.deleteProperty(globalThis, '__psstPasskeyBridge');
  vi.unstubAllGlobals();
});

describe('passkey interceptor installation', () => {
  it('advertises psst as a user-verifying platform authenticator', async () => {
    class StubCredentialsContainer {
      get() {
        return Promise.resolve(null);
      }
    }
    class StubPublicKeyCredential {
      static isUserVerifyingPlatformAuthenticatorAvailable() {
        return Promise.resolve(false);
      }
    }

    vi.stubGlobal('CredentialsContainer', StubCredentialsContainer);
    vi.stubGlobal('PublicKeyCredential', StubPublicKeyCredential);

    installPasskeyInterceptor();

    await expect(
      StubPublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
    ).resolves.toBe(true);
  });
});
