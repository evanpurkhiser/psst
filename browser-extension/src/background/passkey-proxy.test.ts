import {describe, expect, it, vi} from 'vitest';

import type {AssertionResponse} from '../protocol';

import {createPasskeyProxy} from './passkey-proxy';

const handoff = (handoffId: string, challenge = handoffId) => ({
  handoffId,
  origin: 'https://example.com',
  request: {
    challenge,
    rpId: 'example.com',
    allowCredentials: [`credential-${challenge}`],
  },
});

const browserRequest = (requestId: number, challenge: string) => ({
  requestId,
  requestDetailsJson: JSON.stringify({
    challenge,
    rpId: 'example.com',
    allowCredentials: [{id: `credential-${challenge}`}],
  }),
});

const deferred = <Value>() => Promise.withResolvers<Value>();

type SuccessfulResponse = Extract<AssertionResponse, {success: true}>;
type DeferredResponse = ReturnType<typeof deferred<SuccessfulResponse>>;

const successfulResponse = (id: string): SuccessfulResponse => ({
  success: true,
  assertion: {
    id,
    rawId: id,
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: 'client-data',
      authenticatorData: 'authenticator-data',
      signature: 'signature',
      userHandle: 'user',
    },
    clientExtensionResults: {},
  },
});

const setup = () => {
  const noProxyError: string | undefined = undefined;
  const proxy = {
    attach: vi.fn(() => Promise.resolve<string | undefined>(noProxyError)),
    detach: vi.fn(() => Promise.resolve<string | undefined>(noProxyError)),
    completeGetRequest: vi.fn(() => Promise.resolve()),
  };
  const responses = new Map<string, DeferredResponse>();
  const signals = new Map<string, AbortSignal>();
  const requestAssertion = vi.fn((request, signal: AbortSignal) => {
    const response = deferred<SuccessfulResponse>();
    responses.set(request.requestId, response);
    signals.set(request.requestId, signal);
    return response.promise;
  });
  const coordinator = createPasskeyProxy({proxy, requestAssertion});

  return {coordinator, proxy, requestAssertion, responses, signals};
};

describe('passkey proxy', () => {
  it('completes distinct browser requests in parallel', async () => {
    const {coordinator, proxy, requestAssertion, responses} = setup();
    await Promise.all([
      coordinator.arm(handoff('first')),
      coordinator.arm(handoff('second')),
    ]);

    const first = coordinator.handleGetRequest(browserRequest(1, 'first'));
    const second = coordinator.handleGetRequest(browserRequest(2, 'second'));
    expect(requestAssertion).toHaveBeenCalledTimes(2);

    responses.get('first')?.resolve(successfulResponse('first'));
    await first;
    expect(proxy.detach).not.toHaveBeenCalled();

    responses.get('second')?.resolve(successfulResponse('second'));
    await second;
    expect(proxy.completeGetRequest).toHaveBeenCalledTimes(2);
    expect(proxy.detach).toHaveBeenCalledOnce();
  });

  it('keeps the proxy attached until the final waiting handoff is canceled', async () => {
    const {coordinator, proxy} = setup();
    await Promise.all([
      coordinator.arm(handoff('first')),
      coordinator.arm(handoff('second')),
    ]);

    await coordinator.cancel('first');
    expect(proxy.detach).not.toHaveBeenCalled();

    await coordinator.cancel('second');
    expect(proxy.detach).toHaveBeenCalledOnce();
  });

  it('aborts an active daemon request when its handoff is canceled', async () => {
    const {coordinator, proxy, requestAssertion} = setup();
    let activeSignal: AbortSignal | undefined;
    requestAssertion.mockImplementationOnce((_request, signal: AbortSignal) => {
      activeSignal = signal;
      return new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason));
      });
    });
    await coordinator.arm(handoff('first'));
    const activeRequest = coordinator.handleGetRequest(browserRequest(1, 'first'));

    await coordinator.cancel('first');
    await activeRequest;

    expect(activeSignal?.aborted).toBe(true);
    expect(proxy.completeGetRequest).not.toHaveBeenCalled();
  });

  it('fails closed when multiple handoffs match one browser request', async () => {
    const {coordinator, proxy, requestAssertion} = setup();
    await Promise.all([
      coordinator.arm(handoff('first', 'shared')),
      coordinator.arm(handoff('second', 'shared')),
    ]);

    await coordinator.handleGetRequest({
      requestId: 1,
      requestDetailsJson: JSON.stringify({
        challenge: 'shared',
        rpId: 'example.com',
        allowCredentials: [{id: 'credential-shared'}],
      }),
    });

    expect(requestAssertion).not.toHaveBeenCalled();
    expect(proxy.completeGetRequest).toHaveBeenCalledWith({
      requestId: 1,
      error: {
        name: 'NotAllowedError',
        message: 'The WebAuthn request matched multiple psst handoffs',
      },
    });
  });

  it('cleans up when the daemon rejects a request', async () => {
    const {coordinator, proxy, requestAssertion} = setup();
    requestAssertion.mockRejectedValueOnce(new Error('request failed'));
    await coordinator.arm(handoff('first'));

    await coordinator.handleGetRequest(browserRequest(1, 'first'));

    expect(proxy.completeGetRequest).toHaveBeenCalledWith({
      requestId: 1,
      error: {
        name: 'NotAllowedError',
        message: 'The psst browser service is unavailable',
      },
    });
    expect(proxy.detach).toHaveBeenCalledOnce();
  });

  it('reattaches after Chrome fails to detach', async () => {
    const {coordinator, proxy} = setup();
    proxy.detach.mockResolvedValueOnce('detach failed');
    await coordinator.arm(handoff('first'));

    await coordinator.cancel('first');
    await coordinator.arm(handoff('second'));
    await coordinator.cancel('second');

    expect(proxy.attach).toHaveBeenCalledTimes(2);
    expect(proxy.detach).toHaveBeenCalledTimes(2);
  });
});
