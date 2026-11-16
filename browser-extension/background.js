const HOST = 'com.evanpurkhiser.psst';
const REQUEST_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const armingRequests = new Map();
const armedRequests = new Map();
const activeRequests = new Map();
let attachPromise;
let detachPromise;
let proxyAttached = false;

const maybeDetach = async () => {
  if (
    attachPromise ||
    detachPromise ||
    !proxyAttached ||
    armingRequests.size ||
    armedRequests.size ||
    activeRequests.size
  ) {
    return;
  }

  proxyAttached = false;
  detachPromise = chrome.webAuthenticationProxy
    .detach()
    .catch(() => {
      // The extension may already be detached after cancellation or reload.
    })
    .finally(() => {
      detachPromise = undefined;
    });
  await detachPromise;
};

const ensureAttached = async () => {
  if (detachPromise) {
    await detachPromise;
  }
  if (proxyAttached) {
    return;
  }
  if (!attachPromise) {
    attachPromise = chrome.webAuthenticationProxy
      .attach()
      .then(error => {
        if (error) {
          throw new Error(error);
        }
        proxyAttached = true;
      })
      .finally(() => {
        attachPromise = undefined;
        void maybeDetach();
      });
  }
  await attachPromise;
};

const fail = async (requestId, message) => {
  try {
    await chrome.webAuthenticationProxy.completeGetRequest({
      requestId,
      error: {name: 'NotAllowedError', message},
    });
  } finally {
    activeRequests.delete(requestId);
    await maybeDetach();
  }
};

const sameRequest = (expected, actual) => {
  const expectedCredentials = expected.allowCredentials || [];
  const actualCredentials = (actual.allowCredentials || []).map(item => item.id);

  return (
    expected.challenge === actual.challenge &&
    expected.rpId === (actual.rpId || expected.rpId) &&
    JSON.stringify(expectedCredentials) === JSON.stringify(actualCredentials)
  );
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === 'psst.webauthn.cancel') {
    const canceledArming = armingRequests.delete(message.requestId);
    const canceledArmed = armedRequests.delete(message.requestId);
    const active = [...activeRequests.values()].some(
      request => request.handoffId === message.requestId,
    );
    if (!canceledArming && !canceledArmed && !active) {
      sendResponse({success: true});
      return false;
    }

    maybeDetach().then(() => sendResponse({success: true}));
    return true;
  }
  if (message?.type !== 'psst.webauthn.arm') {
    return false;
  }

  const senderUrl = sender.url && new URL(sender.url);
  if (!senderUrl || senderUrl.protocol !== 'https:' || sender.frameId !== 0) {
    sendResponse({success: false, error: 'Passkeys require a top-level HTTPS page'});
    return false;
  }
  if (
    typeof message.requestId !== 'string' ||
    !REQUEST_ID_PATTERN.test(message.requestId)
  ) {
    sendResponse({success: false, error: 'The passkey handoff identifier is invalid'});
    return false;
  }
  if (
    armingRequests.has(message.requestId) ||
    armedRequests.has(message.requestId) ||
    [...activeRequests.values()].some(request => request.handoffId === message.requestId)
  ) {
    sendResponse({success: false, error: 'This psst passkey handoff is already active'});
    return false;
  }

  armingRequests.set(message.requestId, {
    handoffId: message.requestId,
    origin: senderUrl.origin,
    request: message.request,
  });
  ensureAttached()
    .then(() => {
      const request = armingRequests.get(message.requestId);
      if (!request) {
        void maybeDetach();
        sendResponse({success: false, error: 'The psst passkey handoff was canceled'});
        return;
      }
      armingRequests.delete(message.requestId);
      armedRequests.set(message.requestId, request);
      sendResponse({success: true, code: 'proxy_ready'});
    })
    .catch(() => {
      armingRequests.delete(message.requestId);
      void maybeDetach();
      sendResponse({
        success: false,
        code: 'webauthn_proxy_unavailable',
        error: 'Chrome could not activate the psst WebAuthn proxy',
      });
    });
  return true;
});

chrome.webAuthenticationProxy.onGetRequest.addListener(requestInfo => {
  let request;
  try {
    request = JSON.parse(requestInfo.requestDetailsJson);
  } catch {
    void fail(requestInfo.requestId, 'Chrome returned an invalid WebAuthn request');
    return;
  }
  const matches = [...armedRequests.values()].filter(item =>
    sameRequest(item.request, request),
  );
  if (matches.length !== 1) {
    for (const match of matches) {
      armedRequests.delete(match.handoffId);
    }
    const message = matches.length
      ? 'The WebAuthn request matched multiple psst handoffs'
      : 'No psst passkey handoff is ready';
    void fail(requestInfo.requestId, message);
    return;
  }

  const [armedRequest] = matches;
  armedRequests.delete(armedRequest.handoffId);
  activeRequests.set(requestInfo.requestId, armedRequest);
  const assertion = {
    requestId: armedRequest.handoffId,
    origin: armedRequest.origin,
    challenge: request.challenge,
    rpId: request.rpId || armedRequest.request.rpId,
    allowCredentials: (request.allowCredentials || []).map(item => item.id),
  };

  chrome.runtime.sendNativeMessage(HOST, assertion, async response => {
    if (!activeRequests.has(requestInfo.requestId)) {
      return;
    }

    if (chrome.runtime.lastError || !response?.success) {
      await fail(
        requestInfo.requestId,
        response?.error || 'The psst browser bridge is unavailable',
      );
      return;
    }

    try {
      await chrome.webAuthenticationProxy.completeGetRequest({
        requestId: requestInfo.requestId,
        responseJson: JSON.stringify(response.assertion),
      });
    } finally {
      activeRequests.delete(requestInfo.requestId);
      await maybeDetach();
    }
  });
});

chrome.webAuthenticationProxy.onRequestCanceled.addListener(requestId => {
  if (activeRequests.delete(requestId)) {
    void maybeDetach();
  }
});
