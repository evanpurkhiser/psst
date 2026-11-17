import * as z from 'zod/mini';

import type {AssertionRequest} from '../browser-protocol';
import type {AssertionResponse, BackgroundResponse, PasskeyRequest} from '../protocol';

interface HandoffRequest {
  handoffId: string;
  origin: string;
  request: PasskeyRequest;
}

const chromePasskeyRequestSchema = z.object({
  challenge: z.string(),
  rpId: z.optional(z.string()),
  allowCredentials: z.optional(z.array(z.object({id: z.string()}))),
});
type ChromePasskeyRequest = z.infer<typeof chromePasskeyRequestSchema>;

interface WebAuthenticationProxy {
  attach(): Promise<string | undefined>;
  detach(): Promise<string | undefined>;
  completeGetRequest(
    details: chrome.webAuthenticationProxy.GetResponseDetails,
  ): Promise<void>;
}

interface PasskeyProxyDependencies {
  proxy: WebAuthenticationProxy;
  requestAssertion(
    request: AssertionRequest,
    signal: AbortSignal,
  ): Promise<AssertionResponse>;
}

interface PasskeyProxy {
  arm(request: HandoffRequest): Promise<BackgroundResponse>;
  cancel(handoffId: string): Promise<void>;
  handleGetRequest(request: chrome.webAuthenticationProxy.GetRequest): Promise<void>;
  handleRequestCanceled(requestId: number): void;
}

const parseRequest = (value: string): ChromePasskeyRequest | undefined => {
  try {
    const parsed = z.safeParse(chromePasskeyRequestSchema, JSON.parse(value));
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
};

interface ActiveRequest {
  handoff: HandoffRequest;
  abort: AbortController;
}

const sameRequest = (expected: PasskeyRequest, actual: ChromePasskeyRequest) => {
  const actualCredentials = (actual.allowCredentials ?? []).map(item => item.id);

  return (
    expected.challenge === actual.challenge &&
    expected.rpId === (actual.rpId ?? expected.rpId) &&
    JSON.stringify(expected.allowCredentials) === JSON.stringify(actualCredentials)
  );
};

/**
 * Owns the WebAuthn proxy attachment and every in-flight browser handoff.
 */
export const createPasskeyProxy = ({
  proxy,
  requestAssertion,
}: PasskeyProxyDependencies): PasskeyProxy => {
  const arming = new Map<string, HandoffRequest>();
  const armed = new Map<string, HandoffRequest>();
  const active = new Map<number, ActiveRequest>();
  let detachPromise: Promise<void> | undefined;

  const maybeDetach = async () => {
    if (arming.size || armed.size || active.size) {
      return;
    }

    if (!detachPromise) {
      detachPromise = proxy
        .detach()
        .then(error => {
          if (error) {
            throw new Error(error);
          }
        })
        .catch(() => {})
        .finally(() => {
          detachPromise = undefined;
        });
    }
    await detachPromise;
  };

  const ensureAttached = async () => {
    if (detachPromise) {
      await detachPromise;
    }

    const error = await proxy.attach();
    if (error) {
      throw new Error(error);
    }
  };

  const fail = async (requestId: number, message: string) => {
    try {
      await proxy.completeGetRequest({
        requestId,
        error: {name: 'NotAllowedError', message},
      });
    } finally {
      active.delete(requestId);
      await maybeDetach();
    }
  };

  const arm = async (request: HandoffRequest): Promise<BackgroundResponse> => {
    const duplicate =
      arming.has(request.handoffId) ||
      armed.has(request.handoffId) ||
      [...active.values()].some(
        activeRequest => activeRequest.handoff.handoffId === request.handoffId,
      );
    if (duplicate) {
      return {success: false, error: 'This psst passkey handoff is already active'};
    }

    arming.set(request.handoffId, request);
    try {
      await ensureAttached();
    } catch {
      arming.delete(request.handoffId);
      await maybeDetach();
      return {
        success: false,
        code: 'webauthn_proxy_unavailable',
        error: 'Chrome could not activate the psst WebAuthn proxy',
      };
    }

    const waiting = arming.get(request.handoffId);
    if (!waiting) {
      await maybeDetach();
      return {success: false, error: 'The psst passkey handoff was canceled'};
    }

    arming.delete(request.handoffId);
    armed.set(request.handoffId, waiting);
    return {success: true, code: 'proxy_ready'};
  };

  const cancel = async (handoffId: string) => {
    arming.delete(handoffId);
    armed.delete(handoffId);
    for (const [requestId, request] of active) {
      if (request.handoff.handoffId === handoffId) {
        request.abort.abort();
        active.delete(requestId);
      }
    }
    await maybeDetach();
  };

  const handleGetRequest = async (
    requestInfo: chrome.webAuthenticationProxy.GetRequest,
  ) => {
    const request = parseRequest(requestInfo.requestDetailsJson);
    if (!request) {
      await fail(requestInfo.requestId, 'Chrome returned an invalid WebAuthn request');
      return;
    }

    const matches = [...armed.values()].filter(item =>
      sameRequest(item.request, request),
    );
    if (matches.length !== 1) {
      for (const match of matches) {
        armed.delete(match.handoffId);
      }
      const message = matches.length
        ? 'The WebAuthn request matched multiple psst handoffs'
        : 'No psst passkey handoff is ready';
      await fail(requestInfo.requestId, message);
      return;
    }

    const [matched] = matches;
    armed.delete(matched.handoffId);
    const abort = new AbortController();
    active.set(requestInfo.requestId, {handoff: matched, abort});

    let response: AssertionResponse;
    try {
      response = await requestAssertion(
        {
          requestId: matched.handoffId,
          origin: matched.origin,
          challenge: request.challenge,
          rpId: request.rpId ?? matched.request.rpId,
          allowCredentials: (request.allowCredentials ?? []).map(item => item.id),
        },
        abort.signal,
      );
    } catch {
      if (active.has(requestInfo.requestId)) {
        await fail(requestInfo.requestId, 'The psst browser service is unavailable');
      }
      return;
    }
    if (!active.has(requestInfo.requestId)) {
      return;
    }
    if (!response.success) {
      await fail(
        requestInfo.requestId,
        response.error ?? 'The psst browser service is unavailable',
      );
      return;
    }

    try {
      await proxy.completeGetRequest({
        requestId: requestInfo.requestId,
        responseJson: JSON.stringify(response.assertion),
      });
    } finally {
      active.delete(requestInfo.requestId);
      await maybeDetach();
    }
  };

  const handleRequestCanceled = (requestId: number) => {
    const request = active.get(requestId);
    if (request) {
      request.abort.abort();
      active.delete(requestId);
      void maybeDetach();
    }
  };

  return {arm, cancel, handleGetRequest, handleRequestCanceled};
};
