const HOST = "com.evanpurkhiser.psst";
const REQUEST_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

let armedRequest;
let activeRequestId;
let armingRequestId;

const detach = async () => {
  armedRequest = undefined;
  activeRequestId = undefined;
  armingRequestId = undefined;
  try {
    await chrome.webAuthenticationProxy.detach();
  } catch (_) {
    // The extension may already be detached after cancellation or reload.
  }
};

const fail = async (requestId, message) => {
  try {
    await chrome.webAuthenticationProxy.completeGetRequest({
      requestId,
      error: { name: "NotAllowedError", message },
    });
  } finally {
    await detach();
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
  if (message?.type === "psst.webauthn.cancel") {
    const matchesArming = message.requestId === armingRequestId;
    const matchesArmed = message.requestId === armedRequest?.handoffId;
    if (!matchesArming && !matchesArmed) {
      sendResponse({ success: true });
      return false;
    }

    detach().then(() => sendResponse({ success: true }));
    return true;
  }
  if (message?.type !== "psst.webauthn.arm") return false;

  const senderUrl = sender.url && new URL(sender.url);
  if (!senderUrl || senderUrl.protocol !== "https:" || sender.frameId !== 0) {
    sendResponse({ success: false, error: "Passkeys require a top-level HTTPS page" });
    return false;
  }
  if (typeof message.requestId !== "string" || !REQUEST_ID_PATTERN.test(message.requestId)) {
    sendResponse({ success: false, error: "The passkey handoff identifier is invalid" });
    return false;
  }
  if (armingRequestId || armedRequest) {
    sendResponse({ success: false, error: "Another psst passkey handoff is active" });
    return false;
  }

  armingRequestId = message.requestId;
  chrome.webAuthenticationProxy
    .attach()
    .then(error => {
      if (error) throw new Error(error);
      if (armingRequestId !== message.requestId) {
        void detach();
        sendResponse({ success: false, error: "The psst passkey handoff was canceled" });
        return;
      }
      armedRequest = {
        handoffId: message.requestId,
        origin: senderUrl.origin,
        request: message.request,
      };
      armingRequestId = undefined;
      sendResponse({ success: true, code: "proxy_ready" });
    })
    .catch(() => {
      if (armingRequestId === message.requestId) armingRequestId = undefined;
      sendResponse({
        success: false,
        code: "webauthn_proxy_unavailable",
        error: "Chrome could not activate the psst WebAuthn proxy",
      });
    });
  return true;
});

chrome.webAuthenticationProxy.onGetRequest.addListener(requestInfo => {
  if (!armedRequest || activeRequestId !== undefined) {
    void fail(requestInfo.requestId, "No psst passkey handoff is ready");
    return;
  }

  let request;
  try {
    request = JSON.parse(requestInfo.requestDetailsJson);
  } catch (_) {
    void fail(requestInfo.requestId, "Chrome returned an invalid WebAuthn request");
    return;
  }
  if (!sameRequest(armedRequest.request, request)) {
    void fail(requestInfo.requestId, "The WebAuthn request changed after psst authorization");
    return;
  }

  activeRequestId = requestInfo.requestId;
  const assertion = {
    requestId: armedRequest.handoffId,
    origin: armedRequest.origin,
    challenge: request.challenge,
    rpId: request.rpId || armedRequest.request.rpId,
    allowCredentials: (request.allowCredentials || []).map(item => item.id),
  };

  chrome.runtime.sendNativeMessage(HOST, assertion, async response => {
    if (activeRequestId !== requestInfo.requestId) return;

    if (chrome.runtime.lastError || !response?.success) {
      await fail(
        requestInfo.requestId,
        response?.error || "The psst native host is unavailable",
      );
      return;
    }

    try {
      await chrome.webAuthenticationProxy.completeGetRequest({
        requestId: requestInfo.requestId,
        responseJson: JSON.stringify(response.assertion),
      });
    } finally {
      await detach();
    }
  });
});

chrome.webAuthenticationProxy.onRequestCanceled.addListener(requestId => {
  if (requestId === activeRequestId) void detach();
});
