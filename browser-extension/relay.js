const REQUEST_EVENT = 'psst-passkey-request';
const RESPONSE_EVENT = 'psst-passkey-response';
const CANCEL_EVENT = 'psst-passkey-cancel';
const PROXY_READY_EVENT = 'psst-passkey-proxy-ready';
const PROXY_SETTLED_EVENT = 'psst-passkey-proxy-settled';
const FALLBACK_EVENT = 'psst-passkey-fallback';

let activeRequest;

const failureMessage = response => {
  if (
    ['native_host_unavailable', 'browser_bridge_unavailable'].includes(response?.code)
  ) {
    return 'The psst browser integration is unavailable. Continue without psst.';
  }
  if (response?.code === 'browser_peer_unauthorized') {
    return `${response.error}. Add it with psst browser install --peer-uid <UID>.`;
  }
  if (response?.code === 'passkey_handoff_required') {
    return 'The psst handoff expired. Start a new passkey request or continue without psst.';
  }

  return response?.error || 'The psst handoff failed';
};

const respond = (ids, response) => {
  for (const id of ids) {
    window.dispatchEvent(new CustomEvent(RESPONSE_EVENT, {detail: {id, response}}));
  }
};

const closeRequest = request => {
  request.host.remove();
  if (activeRequest === request) {
    activeRequest = undefined;
  }
  if (request.previousFocus?.isConnected) {
    request.previousFocus.focus();
  }
};

const useBrowser = async request => {
  const [id] = request.ids;
  if (request.handoffId) {
    window.dispatchEvent(new CustomEvent(FALLBACK_EVENT, {detail: {id}}));
    try {
      await chrome.runtime.sendMessage({
        type: 'psst.webauthn.cancel',
        requestId: request.handoffId,
      });
    } catch {
      // The native browser flow can still proceed if the worker was unloaded.
    }
  }

  closeRequest(request);
  respond(request.ids, {code: 'use_browser'});
};

const waitForPsst = request => {
  const requestId = request.browserRequestId;
  request.handoffId = requestId;

  chrome.runtime
    .sendMessage({
      type: 'psst.webauthn.arm',
      requestId,
      request: request.request,
    })
    .then(response => {
      if (activeRequest !== request || request.ids.size === 0) {
        return;
      }
      if (response?.success) {
        const [id] = request.ids;
        window.dispatchEvent(new CustomEvent(PROXY_READY_EVENT, {detail: {id}}));
        return;
      }

      request.status.textContent = failureMessage(response);
      request.browser.focus();
    })
    .catch(() => {
      if (activeRequest !== request || request.ids.size === 0) {
        return;
      }
      request.status.textContent = 'The psst browser integration is unavailable';
      request.browser.focus();
    });
};

const showRequest = request => {
  const host = document.createElement('psst-passkey-request');
  const shadow = host.attachShadow({mode: 'closed'});
  const style = document.createElement('style');
  style.textContent = `
    :host {
      all: initial;
      color-scheme: light dark;
    }
    dialog {
      border: 1px solid GrayText;
      border-radius: 0.5rem;
      box-shadow: 0 0.5rem 1.5rem rgb(0 0 0 / 25%);
      font: 0.875rem/1.5 system-ui, sans-serif;
      inset: 1rem 1rem auto auto;
      margin: 0;
      max-width: min(24rem, calc(100vw - 2rem));
      padding: 1rem;
      position: fixed;
      z-index: 2147483647;
    }
    h2 { margin: 0 0 0.5rem; }
    p { margin: 0 0 0.75rem; }
    label { display: grid; gap: 0.25rem; margin-block: 1rem; }
    input, button { font: inherit; }
    input {
      box-sizing: border-box;
      padding: 0.5rem;
      width: 100%;
    }
    footer { margin-top: 1rem; }
    button {
      cursor: pointer;
      padding: 0.5rem 0.75rem;
    }
  `;

  const dialog = document.createElement('dialog');
  dialog.open = true;
  dialog.setAttribute('aria-labelledby', 'psst-passkey-title');

  const title = document.createElement('h2');
  title.id = 'psst-passkey-title';
  title.textContent = 'Waiting for psst';

  const description = document.createElement('p');
  description.append('A passkey was requested by ');
  const origin = document.createElement('code');
  origin.textContent = location.origin;
  description.append(origin, ` for ${request.request.rpId}.`);

  const footer = document.createElement('footer');
  const browser = document.createElement('button');
  browser.type = 'button';
  browser.textContent = 'Continue without psst';
  footer.append(browser);

  const status = document.createElement('output');
  status.textContent =
    'Run psst passkey handoff SESSION_REFERENCE with this browser request ID.';

  const requestIdLabel = document.createElement('label');
  requestIdLabel.append('Browser request ID');
  const requestId = document.createElement('input');
  requestId.type = 'text';
  requestId.readOnly = true;
  requestId.value = request.browserRequestId;
  requestIdLabel.append(requestId);

  dialog.append(title, description, requestIdLabel, status, footer);
  shadow.append(style, dialog);
  document.documentElement.append(host);

  request.host = host;
  request.previousFocus =
    document.activeElement instanceof HTMLElement ? document.activeElement : undefined;
  request.browser = browser;
  request.status = status;
  browser.addEventListener('click', () => useBrowser(request));
  dialog.addEventListener('keydown', event => {
    if (event.key !== 'Escape') {
      return;
    }

    event.preventDefault();
    useBrowser(request);
  });
  browser.focus();
};

window.addEventListener(REQUEST_EVENT, event => {
  const {id, request} = event.detail || {};
  if (typeof id !== 'string' || typeof request !== 'object' || request === null) {
    return;
  }

  const key = JSON.stringify(request);
  if (activeRequest) {
    if (activeRequest.key === key) {
      activeRequest.ids.add(id);
    } else {
      respond([id], {
        success: false,
        error: 'Another passkey request is already waiting for psst',
      });
    }
    return;
  }

  activeRequest = {
    ids: new Set([id]),
    key,
    request,
    browserRequestId: crypto.randomUUID(),
  };
  showRequest(activeRequest);
  waitForPsst(activeRequest);
});

window.addEventListener(CANCEL_EVENT, event => {
  const id = event.detail?.id;
  if (!activeRequest || typeof id !== 'string') {
    return;
  }

  activeRequest.ids.delete(id);
  if (activeRequest.ids.size !== 0) {
    return;
  }

  const request = activeRequest;
  closeRequest(request);
  if (request.handoffId) {
    void chrome.runtime.sendMessage({
      type: 'psst.webauthn.cancel',
      requestId: request.handoffId,
    });
  }
});

window.addEventListener(PROXY_SETTLED_EVENT, event => {
  if (!activeRequest || !activeRequest.ids.has(event.detail?.id)) {
    return;
  }
  closeRequest(activeRequest);
});
