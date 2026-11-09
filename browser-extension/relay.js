const REQUEST_EVENT = "psst-passkey-request";
const RESPONSE_EVENT = "psst-passkey-response";
const CANCEL_EVENT = "psst-passkey-cancel";

let activeRequest;

const failureMessage = response => {
  if (["native_host_unavailable", "browser_bridge_unavailable"].includes(response?.code)) {
    return "PSST is not ready. Open a PSST session, then try again.";
  }
  if (response?.code === "browser_peer_unauthorized") {
    return (
      "This browser is not authorized for PSST. " +
      "Inspect psst browser status and install its peer UID."
    );
  }
  if (response?.code === "passkey_handoff_required") {
    return "The PSST handoff expired. Try PSST again or continue with browser.";
  }

  return response?.error || "The PSST handoff failed";
};

const respond = (ids, response) => {
  for (const id of ids) {
    window.dispatchEvent(new CustomEvent(RESPONSE_EVENT, { detail: { id, response } }));
  }
};

const closeRequest = request => {
  request.host.remove();
  if (activeRequest === request) activeRequest = undefined;
  if (request.previousFocus?.isConnected) request.previousFocus.focus();
};

const useBrowser = request => {
  closeRequest(request);
  respond(request.ids, { code: "use_browser" });
};

const usePsst = request => {
  const requestId = crypto.randomUUID();
  request.psst.disabled = true;
  request.browser.focus();
  request.status.textContent = `PSST handoff ${requestId} is waiting. Run psst passkey handoff <session> ${requestId}`;

  chrome.runtime
    .sendMessage({
      type: "psst.webauthn.assert",
      requestId,
      request: request.request,
    })
    .then(response => {
      if (activeRequest !== request || request.ids.size === 0) return;
      if (response?.success) {
        closeRequest(request);
        respond(request.ids, response);
        return;
      }

      request.psst.disabled = false;
      request.psst.textContent = "Try PSST again";
      request.status.textContent = failureMessage(response);
      request.psst.focus();
    })
    .catch(() => {
      if (activeRequest !== request || request.ids.size === 0) return;
      request.psst.disabled = false;
      request.psst.textContent = "Try PSST again";
      request.status.textContent = "The PSST browser integration is unavailable";
      request.psst.focus();
    });
};

const showRequest = request => {
  const host = document.createElement("psst-passkey-request");
  const shadow = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = `
    :host { all: initial; }
    .dialog {
      background: #17151c;
      border: 1px solid #6c5fc7;
      border-radius: 10px;
      box-shadow: 0 12px 36px rgb(0 0 0 / 45%);
      color: #f6f3ff;
      font: 14px/1.45 system-ui, sans-serif;
      inset: 16px 16px auto auto;
      max-width: 390px;
      padding: 16px;
      position: fixed;
      z-index: 2147483647;
    }
    h2 { font: 600 16px/1.3 system-ui, sans-serif; margin: 0 0 8px; }
    p { margin: 0 0 12px; overflow-wrap: anywhere; }
    .origin { color: #c8c0ef; font-family: ui-monospace, monospace; }
    .actions { display: flex; gap: 8px; }
    button {
      background: #6c5fc7;
      border: 0;
      border-radius: 6px;
      color: white;
      cursor: pointer;
      font: 600 14px/1 system-ui, sans-serif;
      padding: 10px 12px;
    }
    button.secondary { background: #3a3643; }
    button:disabled { cursor: wait; opacity: 0.55; }
    .status { color: #d8d2e8; margin: 12px 0 0; }
  `;

  const dialog = document.createElement("section");
  dialog.className = "dialog";
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-labelledby", "psst-passkey-title");

  const title = document.createElement("h2");
  title.id = "psst-passkey-title";
  title.textContent = "Passkey requested";

  const description = document.createElement("p");
  description.append("A passkey was requested by ");
  const origin = document.createElement("span");
  origin.className = "origin";
  origin.textContent = location.origin;
  description.append(origin, ` for ${request.request.rpId}.`);

  const actions = document.createElement("div");
  actions.className = "actions";
  const psst = document.createElement("button");
  psst.type = "button";
  psst.textContent = "Use PSST";
  const browser = document.createElement("button");
  browser.type = "button";
  browser.className = "secondary";
  browser.textContent = "Continue with browser";
  actions.append(psst, browser);

  const status = document.createElement("p");
  status.className = "status";
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  status.textContent = "Choose how to complete this passkey request.";

  dialog.append(title, description, actions, status);
  shadow.append(style, dialog);
  document.documentElement.append(host);

  request.host = host;
  request.previousFocus =
    document.activeElement instanceof HTMLElement ? document.activeElement : undefined;
  request.psst = psst;
  request.browser = browser;
  request.status = status;
  psst.addEventListener("click", () => usePsst(request));
  browser.addEventListener("click", () => useBrowser(request));
  dialog.addEventListener("keydown", event => {
    if (event.key !== "Escape") return;

    event.preventDefault();
    useBrowser(request);
  });
  browser.focus();
};

window.addEventListener(REQUEST_EVENT, event => {
  const { id, request } = event.detail || {};
  if (typeof id !== "string" || typeof request !== "object" || request === null) return;

  const key = JSON.stringify(request);
  if (activeRequest) {
    if (activeRequest.key === key) {
      activeRequest.ids.add(id);
    } else {
      respond([id], {
        success: false,
        error: "Another passkey request is already awaiting a choice",
      });
    }
    return;
  }

  activeRequest = { ids: new Set([id]), key, request };
  showRequest(activeRequest);
});

window.addEventListener(CANCEL_EVENT, event => {
  const id = event.detail?.id;
  if (!activeRequest || typeof id !== "string") return;

  activeRequest.ids.delete(id);
  if (activeRequest.ids.size === 0) closeRequest(activeRequest);
});
