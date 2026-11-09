const HOST = "com.evanpurkhiser.psst";
const pendingAssertions = new Map();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "psst.webauthn.assert") return false;

  const senderUrl = sender.url && new URL(sender.url);
  if (!senderUrl || senderUrl.protocol !== "https:" || sender.frameId !== 0) {
    sendResponse({ success: false, error: "Passkeys require a top-level HTTPS page" });
    return false;
  }

  const assertion = { ...message.request, origin: senderUrl.origin };
  const key = JSON.stringify(assertion);
  const pending = pendingAssertions.get(key);
  if (pending) {
    pending.push(sendResponse);
    return true;
  }

  pendingAssertions.set(key, [sendResponse]);
  chrome.runtime.sendNativeMessage(HOST, { ...assertion, requestId: message.id }, response => {
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
