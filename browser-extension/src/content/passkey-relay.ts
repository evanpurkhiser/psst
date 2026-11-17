import * as z from 'zod/mini';

import {dispatchPageEvent, listenForPageEvent} from '../page-events';
import {
  backgroundResponseSchema,
  events,
  type ArmMessage,
  type BackgroundResponse,
  type CancelMessage,
  type PasskeyRequest,
  type RelayResponse,
} from '../protocol';

import {showPasskeyPrompt, type PasskeyPrompt} from './passkey-prompt';

interface ActiveRequest {
  ids: Set<string>;
  key: string;
  request: PasskeyRequest;
  browserRequestId: string;
  handoffId?: string;
  prompt?: PasskeyPrompt;
}

const failureMessage = (response: BackgroundResponse) => {
  if (
    !response.success &&
    ['native_host_unavailable', 'browser_bridge_unavailable'].includes(
      response.code ?? '',
    )
  ) {
    return 'The psst browser integration is unavailable. Continue without psst.';
  }
  if (!response.success && response.code === 'passkey_handoff_required') {
    return 'The psst handoff expired. Start a new passkey request or continue without psst.';
  }

  return response.success ? '' : response.error;
};

/**
 * Connects page-world WebAuthn requests to Chrome extension messaging and UI.
 */
export const installPasskeyRelay = () => {
  let active: ActiveRequest | undefined;

  const respond = (ids: Iterable<string>, response: RelayResponse) => {
    for (const id of ids) {
      dispatchPageEvent(events.response, {id, response});
    }
  };

  const close = (request: ActiveRequest) => {
    request.prompt?.close();
    if (active === request) {
      active = undefined;
    }
  };

  const useBrowser = async (request: ActiveRequest) => {
    const [id] = request.ids;
    if (request.handoffId) {
      dispatchPageEvent(events.fallback, {id});
      try {
        const message: CancelMessage = {
          type: 'psst.webauthn.cancel',
          requestId: request.handoffId,
        };
        await chrome.runtime.sendMessage(message);
      } catch {
        // The native browser flow can still proceed if the worker was unloaded.
      }
    }

    close(request);
    respond(request.ids, {code: 'use_browser'});
  };

  const waitForPsst = (request: ActiveRequest) => {
    request.handoffId = request.browserRequestId;
    const message: ArmMessage = {
      type: 'psst.webauthn.arm',
      requestId: request.browserRequestId,
      request: request.request,
    };

    chrome.runtime
      .sendMessage<ArmMessage, unknown>(message)
      .then(value => {
        if (active !== request || request.ids.size === 0) {
          return;
        }
        const parsed = z.safeParse(backgroundResponseSchema, value);
        if (!parsed.success) {
          throw new Error('The browser worker returned an invalid response');
        }
        const response = parsed.data;

        if (response.success) {
          const [id] = request.ids;
          dispatchPageEvent(events.proxyReady, {id});
          return;
        }

        request.prompt?.showStatus(failureMessage(response));
        request.prompt?.focusContinue();
      })
      .catch(() => {
        if (active !== request || request.ids.size === 0) {
          return;
        }
        request.prompt?.showStatus('The psst browser integration is unavailable');
        request.prompt?.focusContinue();
      });
  };

  listenForPageEvent(events.request, detail => {
    const key = JSON.stringify(detail.request);
    if (active) {
      if (active.key === key) {
        active.ids.add(detail.id);
      } else {
        respond([detail.id], {
          success: false,
          error: 'Another passkey request is already waiting for psst',
        });
      }
      return;
    }

    const request: ActiveRequest = {
      ids: new Set([detail.id]),
      key,
      request: detail.request,
      browserRequestId: crypto.randomUUID(),
    };
    active = request;
    request.prompt = showPasskeyPrompt({
      origin: location.origin,
      rpId: request.request.rpId,
      requestId: request.browserRequestId,
      continueWithoutPsst: () => void useBrowser(request),
    });
    waitForPsst(request);
  });

  listenForPageEvent(events.cancel, detail => {
    if (!active) {
      return;
    }

    active.ids.delete(detail.id);
    if (active.ids.size !== 0) {
      return;
    }

    const request = active;
    close(request);
    if (request.handoffId) {
      const message: CancelMessage = {
        type: 'psst.webauthn.cancel',
        requestId: request.handoffId,
      };
      void chrome.runtime.sendMessage(message);
    }
  });

  listenForPageEvent(events.proxySettled, detail => {
    if (active?.ids.has(detail.id)) {
      close(active);
    }
  });
};
