import {afterEach, describe, expect, it, vi} from 'vitest';

import type {AssertionRequest} from '../browser-protocol';

import {requestAssertion} from './psst-client';

const request: AssertionRequest = {
  requestId: '410e26bd-7701-4481-8b7e-9f4215edbd8d',
  origin: 'https://example.com',
  challenge: 'challenge',
  rpId: 'example.com',
  allowCredentials: ['credential'],
};

const assertion = {
  id: 'credential',
  rawId: 'credential',
  type: 'public-key',
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: 'client-data',
    authenticatorData: 'authenticator-data',
    signature: 'signature',
    userHandle: 'user',
  },
  clientExtensionResults: {},
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('psst browser client', () => {
  it('long-polls until the assertion is ready and then cancels the request', async () => {
    let polls = 0;
    const fetch = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      if (init?.method === 'POST') {
        return Response.json({capability: 'private-capability'}, {status: 201});
      }
      if (init?.method === 'DELETE') {
        return new Response(null, {status: 204});
      }

      polls += 1;
      return polls === 1
        ? new Response(null, {status: 204})
        : Response.json({status: 'complete', assertion});
    });
    vi.stubGlobal('fetch', fetch);

    await expect(
      requestAssertion(request, new AbortController().signal),
    ).resolves.toEqual({success: true, assertion});
    expect(polls).toBe(2);
    expect(fetch).toHaveBeenLastCalledWith(
      'http://host.containers.internal:7338/passkey-requests/410e26bd-7701-4481-8b7e-9f4215edbd8d',
      {
        method: 'DELETE',
        headers: {Authorization: 'Bearer private-capability'},
      },
    );
  });

  it('rejects responses outside the generated Rust protocol', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        Response.json({capability: 'private-capability'}, {status: 201}),
      )
      .mockResolvedValueOnce(
        Response.json({status: 'complete', assertion: {id: 'incomplete'}}),
      )
      .mockResolvedValueOnce(new Response(null, {status: 204}));
    vi.stubGlobal('fetch', fetch);

    await expect(
      requestAssertion(request, new AbortController().signal),
    ).resolves.toEqual({
      success: false,
      error: 'psst returned an invalid passkey response',
    });
  });
});
