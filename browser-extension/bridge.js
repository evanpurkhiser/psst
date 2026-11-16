(() => {
  if (window !== window.top || globalThis.__psstPasskeyBridge) return;

  const REQUEST_EVENT = "psst-passkey-request";
  const RESPONSE_EVENT = "psst-passkey-response";
  const CANCEL_EVENT = "psst-passkey-cancel";
  const PROXY_READY_EVENT = "psst-passkey-proxy-ready";
  const PROXY_SETTLED_EVENT = "psst-passkey-proxy-settled";
  const FALLBACK_EVENT = "psst-passkey-fallback";
  const nativeGet = CredentialsContainer.prototype.get;
  const pending = new Map();

  const encode = value => {
    const bytes = new Uint8Array(value);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  };

  const requestFor = options => ({
    challenge: encode(options.publicKey.challenge),
    rpId: options.publicKey.rpId || location.hostname,
    allowCredentials: (options.publicKey.allowCredentials || []).map(item => encode(item.id)),
  });

  const rejectAll = (operation, error) => {
    pending.delete(operation.key);
    for (const subscriber of operation.subscribers) {
      subscriber.signal?.removeEventListener("abort", subscriber.abort);
      subscriber.reject(error);
    }
    operation.subscribers.clear();
  };

  const resolveAll = (operation, credential) => {
    pending.delete(operation.key);
    for (const subscriber of operation.subscribers) {
      subscriber.signal?.removeEventListener("abort", subscriber.abort);
      subscriber.resolve(credential);
    }
    operation.subscribers.clear();
  };

  const runNative = operation => {
    if (operation.started) return;
    operation.started = true;
    const attempt = ++operation.attempt;

    const options = { ...operation.options, signal: operation.controller.signal };
    Reflect.apply(nativeGet, operation.container, [options]).then(
      credential => {
        if (attempt !== operation.attempt) return;
        resolveAll(operation, credential);
        window.dispatchEvent(
          new CustomEvent(PROXY_SETTLED_EVENT, { detail: { id: operation.id, success: true } }),
        );
      },
      error => {
        if (attempt !== operation.attempt) return;
        rejectAll(operation, error);
        window.dispatchEvent(
          new CustomEvent(PROXY_SETTLED_EVENT, {
            detail: { id: operation.id, success: false, error: error?.message },
          }),
        );
      },
    );
  };

  const finish = event => {
    const operation = [...pending.values()].find(item => item.id === event.detail?.id);
    if (!operation) return;

    const response = event.detail.response;
    if (response?.code === "use_browser") {
      operation.controller = new AbortController();
      operation.started = false;
      runNative(operation);
      return;
    }
    if (!response?.success) {
      rejectAll(
        operation,
        new DOMException(response?.error || "psst passkey signing failed", "NotAllowedError"),
      );
    }
  };

  const proxyReady = event => {
    const operation = [...pending.values()].find(item => item.id === event.detail?.id);
    if (operation) runNative(operation);
  };

  const fallback = event => {
    const operation = [...pending.values()].find(item => item.id === event.detail?.id);
    if (!operation || !operation.started) return;

    operation.attempt++;
    operation.started = false;
    operation.controller.abort();
  };

  const subscribe = (operation, signal) =>
    new Promise((resolve, reject) => {
      const abort = () => {
        if (!operation.subscribers.delete(subscriber)) return;
        reject(new DOMException("The operation was aborted", "AbortError"));
        if (operation.subscribers.size !== 0) return;

        pending.delete(operation.key);
        operation.attempt++;
        operation.controller.abort();
        window.dispatchEvent(new CustomEvent(CANCEL_EVENT, { detail: { id: operation.id } }));
      };
      const subscriber = { resolve, reject, signal, abort };
      operation.subscribers.add(subscriber);

      if (signal?.aborted) {
        abort();
        return;
      }
      signal?.addEventListener("abort", abort, { once: true });
    });

  CredentialsContainer.prototype.get = function (options = {}) {
    if (!options.publicKey || options.mediation === "silent") {
      return Reflect.apply(nativeGet, this, arguments);
    }

    const request = requestFor(options);
    const key = JSON.stringify(request);
    let operation = pending.get(key);
    if (!operation) {
      operation = {
        id: crypto.randomUUID(),
        key,
        request,
        options,
        container: this,
        controller: new AbortController(),
        subscribers: new Set(),
        started: false,
        attempt: 0,
      };
      pending.set(key, operation);
      window.dispatchEvent(
        new CustomEvent(REQUEST_EVENT, { detail: { id: operation.id, request } }),
      );
    }

    return subscribe(operation, options.signal);
  };

  window.addEventListener(RESPONSE_EVENT, finish);
  window.addEventListener(PROXY_READY_EVENT, proxyReady);
  window.addEventListener(FALLBACK_EVENT, fallback);
  Object.defineProperty(globalThis, "__psstPasskeyBridge", { value: true });
})();
