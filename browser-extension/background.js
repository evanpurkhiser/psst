const HOST = "com.evanpurkhiser.psst";
const MAX_PENDING_ASSERTIONS = 1;
const REQUEST_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const pendingAssertions = new Map();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "psst.webauthn.assert") return false;

  const senderUrl = sender.url && new URL(sender.url);
  if (!senderUrl || senderUrl.protocol !== "https:" || sender.frameId !== 0) {
    sendResponse({ success: false, error: "Passkeys require a top-level HTTPS page" });
    return false;
  }

  if (typeof message.requestId !== "string" || !REQUEST_ID_PATTERN.test(message.requestId)) {
    sendResponse({ success: false, error: "The passkey handoff identifier is invalid" });
    return false;
  }

  const assertion = { ...message.request, origin: senderUrl.origin };
  const key = `${sender.tab?.id ?? "unknown"}:${JSON.stringify(assertion)}`;
  const pending = pendingAssertions.get(key);
  if (pending) {
    pending.push(sendResponse);
    return true;
  }

  if (pendingAssertions.size >= MAX_PENDING_ASSERTIONS) {
    sendResponse({ success: false, error: "Too many PSST passkey handoffs are active" });
    return false;
  }

  pendingAssertions.set(key, [sendResponse]);
  chrome.runtime.sendNativeMessage(HOST, { ...assertion, requestId: message.requestId }, response => {
    const callbacks = pendingAssertions.get(key) || [];
    pendingAssertions.delete(key);

    if (chrome.runtime.lastError) {
      response = {
        success: false,
        code: "native_host_unavailable",
        error: "The PSST native host is unavailable",
      };
    }

    for (const callback of callbacks) callback(response);
  });
  return true;
});
