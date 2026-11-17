import * as z from 'zod/mini';

import {createPasskeyProxy} from './background/passkey-proxy';
import {requestAssertion} from './background/psst-client';
import {backgroundMessageSchema} from './protocol';

const requestIdPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const proxy = createPasskeyProxy({
  proxy: chrome.webAuthenticationProxy,
  requestAssertion,
});

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  const parsed = z.safeParse(backgroundMessageSchema, message);
  if (!parsed.success) {
    return false;
  }
  const request = parsed.data;

  if (request.type === 'psst.webauthn.cancel') {
    void proxy.cancel(request.requestId).then(() => sendResponse({success: true}));
    return true;
  }

  let senderUrl: URL | undefined;
  try {
    senderUrl = sender.url ? new URL(sender.url) : undefined;
  } catch {
    senderUrl = undefined;
  }
  if (!senderUrl || senderUrl.protocol !== 'https:' || sender.frameId !== 0) {
    sendResponse({success: false, error: 'Passkeys require a top-level HTTPS page'});
    return false;
  }
  if (!requestIdPattern.test(request.requestId)) {
    sendResponse({success: false, error: 'The passkey handoff identifier is invalid'});
    return false;
  }

  void proxy
    .arm({
      handoffId: request.requestId,
      origin: senderUrl.origin,
      request: request.request,
    })
    .then(sendResponse);
  return true;
});

chrome.webAuthenticationProxy.onGetRequest.addListener(request => {
  void proxy.handleGetRequest(request);
});

chrome.webAuthenticationProxy.onRequestCanceled.addListener(requestId => {
  proxy.handleRequestCanceled(requestId);
});
