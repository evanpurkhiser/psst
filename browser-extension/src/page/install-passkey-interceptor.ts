import {dispatchPageEvent, listenForPageEvent} from '../page-events';
import {events} from '../protocol';

import {createPasskeyInterceptor} from './passkey-interceptor';

/**
 * Connects the passkey interceptor to the page's Credentials API and events.
 */
export const installPasskeyInterceptor = () => {
  if (window !== window.top || Reflect.has(globalThis, '__psstPasskeyBridge')) {
    return;
  }

  const nativeGet = CredentialsContainer.prototype.get;
  const interceptor = createPasskeyInterceptor({
    invokeNative: (container, options) => nativeGet.call(container, options),
    createId: () => crypto.randomUUID(),
    requestProxy: (id, request) => {
      dispatchPageEvent(events.request, {id, request});
    },
    cancelProxy: id => {
      dispatchPageEvent(events.cancel, {id});
    },
    settleProxy: (id, success, error) => {
      dispatchPageEvent(events.proxySettled, {id, success, error});
    },
  });

  CredentialsContainer.prototype.get = function (options = {}) {
    return interceptor.intercept(this, options);
  };
  Object.defineProperty(
    PublicKeyCredential,
    'isUserVerifyingPlatformAuthenticatorAvailable',
    {
      configurable: true,
      value: () => Promise.resolve(true),
      writable: true,
    },
  );

  listenForPageEvent(events.response, ({id, response}) => {
    interceptor.handleResponse(id, response);
  });
  listenForPageEvent(events.proxyReady, ({id}) => {
    interceptor.handleProxyReady(id);
  });
  listenForPageEvent(events.fallback, ({id}) => {
    interceptor.handleFallback(id);
  });
  Object.defineProperty(globalThis, '__psstPasskeyBridge', {value: true});
};
