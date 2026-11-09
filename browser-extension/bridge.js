(() => {
  if (window !== window.top || globalThis.__psstPasskeyBridge) return;

  const REQUEST_EVENT = "psst-passkey-request";
  const RESPONSE_EVENT = "psst-passkey-response";
  const CANCEL_EVENT = "psst-passkey-cancel";
  const nativeGet = CredentialsContainer.prototype.get;

  const encode = value => {
    const bytes = new Uint8Array(value);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  };

  const decode = value => {
    const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (value.length % 4)) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, char => char.charCodeAt(0)).buffer;
  };

  const credential = assertion => {
    const clientExtensionResults = assertion.clientExtensionResults || {};

    return {
      id: assertion.id,
      rawId: decode(assertion.rawId),
      type: assertion.type,
      authenticatorAttachment: assertion.authenticatorAttachment,
      response: {
        clientDataJSON: decode(assertion.response.clientDataJSON),
        authenticatorData: decode(assertion.response.authenticatorData),
        signature: decode(assertion.response.signature),
        userHandle: assertion.response.userHandle ? decode(assertion.response.userHandle) : null,
      },
      getClientExtensionResults: () => clientExtensionResults,
      toJSON: () => ({
        id: assertion.id,
        rawId: assertion.rawId,
        type: assertion.type,
        authenticatorAttachment: assertion.authenticatorAttachment,
        response: assertion.response,
        clientExtensionResults,
      }),
    };
  };

  CredentialsContainer.prototype.get = function (options = {}) {
    if (!options.publicKey) return Reflect.apply(nativeGet, this, arguments);

    const id = crypto.randomUUID();
    const container = this;
    const request = {
      challenge: encode(options.publicKey.challenge),
      rpId: options.publicKey.rpId || location.hostname,
      allowCredentials: (options.publicKey.allowCredentials || []).map(item => encode(item.id)),
    };

    return new Promise((resolve, reject) => {
      const finish = event => {
        if (event.detail?.id !== id) return;
        window.removeEventListener(RESPONSE_EVENT, finish);
        options.signal?.removeEventListener("abort", abort);

        const response = event.detail.response;
        if (response?.code === "use_browser") {
          resolve(Reflect.apply(nativeGet, container, [options]));
          return;
        }
        if (!response?.success) {
          reject(new DOMException(response?.error || "psst passkey signing failed", "NotAllowedError"));
          return;
        }
        resolve(credential(response.assertion));
      };
      const abort = () => {
        window.removeEventListener(RESPONSE_EVENT, finish);
        window.dispatchEvent(new CustomEvent(CANCEL_EVENT, { detail: { id } }));
        reject(new DOMException("The operation was aborted", "AbortError"));
      };

      if (options.signal?.aborted) {
        abort();
        return;
      }
      window.addEventListener(RESPONSE_EVENT, finish);
      options.signal?.addEventListener("abort", abort, { once: true });
      window.dispatchEvent(new CustomEvent(REQUEST_EVENT, { detail: { id, request } }));
    });
  };

  Object.defineProperty(globalThis, "__psstPasskeyBridge", { value: true });
})();
