const REQUEST_EVENT = "psst-passkey-request";
const RESPONSE_EVENT = "psst-passkey-response";

window.addEventListener(REQUEST_EVENT, event => {
  const { id, request } = event.detail || {};
  if (typeof id !== "string" || typeof request !== "object" || request === null) return;

  chrome.runtime
    .sendMessage({ type: "psst.webauthn.assert", id, request })
    .then(response => {
      window.dispatchEvent(new CustomEvent(RESPONSE_EVENT, { detail: { id, response } }));
    })
    .catch(() => {
      window.dispatchEvent(
        new CustomEvent(RESPONSE_EVENT, {
          detail: { id, response: { success: false, error: "PSST passkey signing failed" } },
        }),
      );
    });
});
