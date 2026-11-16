import {describe, expect, it, vi} from 'vitest';

import {createPasskeyInterceptor} from './passkey-interceptor';

const container = {} as CredentialsContainer;
const credential = {id: 'credential'} as Credential;
const options = (signal?: AbortSignal): CredentialRequestOptions => ({
  publicKey: {
    challenge: new Uint8Array([1, 2, 3]),
    rpId: 'example.com',
    allowCredentials: [],
  },
  signal,
});

const deferred = <Value>() => Promise.withResolvers<Value>();

const setup = (
  invokeNative = vi.fn(() => Promise.resolve<Credential | null>(credential)),
) => {
  const requestProxy = vi.fn();
  const cancelProxy = vi.fn();
  const settleProxy = vi.fn();
  const interceptor = createPasskeyInterceptor({
    invokeNative,
    createId: () => 'operation-id',
    requestProxy,
    cancelProxy,
    settleProxy,
  });

  return {interceptor, invokeNative, requestProxy, cancelProxy, settleProxy};
};

describe('passkey interceptor', () => {
  it('shares one native request between equivalent subscribers', async () => {
    const {interceptor, invokeNative, requestProxy, settleProxy} = setup();

    const first = interceptor.intercept(container, options());
    const second = interceptor.intercept(container, options());
    expect(requestProxy).toHaveBeenCalledOnce();

    interceptor.handleProxyReady('operation-id');

    await expect(first).resolves.toBe(credential);
    await expect(second).resolves.toBe(credential);
    expect(invokeNative).toHaveBeenCalledOnce();
    expect(settleProxy).toHaveBeenCalledWith('operation-id', true);
  });

  it('cancels the proxy only after the final subscriber aborts', async () => {
    const {interceptor, cancelProxy} = setup();
    const firstController = new AbortController();
    const secondController = new AbortController();
    const first = interceptor.intercept(container, options(firstController.signal));
    const second = interceptor.intercept(container, options(secondController.signal));

    firstController.abort();
    await expect(first).rejects.toMatchObject({name: 'AbortError'});
    expect(cancelProxy).not.toHaveBeenCalled();

    secondController.abort();
    await expect(second).rejects.toMatchObject({name: 'AbortError'});
    expect(cancelProxy).toHaveBeenCalledWith('operation-id');
  });

  it('ignores a stale completion after browser fallback', async () => {
    const proxied = deferred<Credential | null>();
    const browser = deferred<Credential | null>();
    const invokeNative = vi
      .fn<() => Promise<Credential | null>>()
      .mockReturnValueOnce(proxied.promise)
      .mockReturnValueOnce(browser.promise);
    const {interceptor, settleProxy} = setup(invokeNative);
    const result = interceptor.intercept(container, options());

    interceptor.handleProxyReady('operation-id');
    interceptor.handleFallback('operation-id');
    interceptor.handleResponse('operation-id', {code: 'use_browser'});

    proxied.resolve({id: 'stale'} as Credential);
    await Promise.resolve();
    expect(settleProxy).not.toHaveBeenCalled();

    browser.resolve(credential);
    await expect(result).resolves.toBe(credential);
    expect(invokeNative).toHaveBeenCalledTimes(2);
    expect(settleProxy).toHaveBeenCalledWith('operation-id', true);
  });
});
