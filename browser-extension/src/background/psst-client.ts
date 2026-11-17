import * as z from 'zod/mini';

import {
  ErrorResponseSchema,
  PasskeyResultSchema,
  RegistrationSchema,
  type AssertionRequest,
} from '../browser-protocol';
import type {AssertionResponse} from '../protocol';

const API = 'http://host.containers.internal:7338';

const messageFrom = async (response: Response, fallback: string) => {
  try {
    const parsed = z.safeParse(ErrorResponseSchema, await response.json());
    return parsed.success ? parsed.data.message : fallback;
  } catch {
    return fallback;
  }
};

const cancel = async (requestId: string, capability: string) => {
  try {
    await fetch(`${API}/passkey-requests/${requestId}`, {
      method: 'DELETE',
      headers: {Authorization: `Bearer ${capability}`},
    });
  } catch {
    // The daemon also expires abandoned requests.
  }
};

/**
 * Registers a proxied Chrome request and waits for its authorized assertion.
 */
export const requestAssertion = async (
  request: AssertionRequest,
  signal: AbortSignal,
): Promise<AssertionResponse> => {
  const registrationResponse = await fetch(`${API}/passkey-requests`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(request),
    signal,
  });
  if (!registrationResponse.ok) {
    return {
      success: false,
      error: await messageFrom(
        registrationResponse,
        'psst could not register the passkey request',
      ),
    };
  }

  const registration = z.safeParse(RegistrationSchema, await registrationResponse.json());
  if (!registration.success) {
    return {success: false, error: 'psst returned an invalid registration'};
  }
  const {capability} = registration.data;

  try {
    while (!signal.aborted) {
      const response = await fetch(`${API}/passkey-requests/${request.requestId}`, {
        headers: {Authorization: `Bearer ${capability}`},
        signal,
      });
      if (response.status === 204) {
        continue;
      }
      if (!response.ok && response.status !== 410) {
        return {
          success: false,
          error: await messageFrom(
            response,
            'psst could not complete the passkey request',
          ),
        };
      }

      const result = z.safeParse(PasskeyResultSchema, await response.json());
      if (!result.success) {
        return {success: false, error: 'psst returned an invalid passkey response'};
      }
      if (result.data.status === 'complete') {
        return {success: true, assertion: result.data.assertion};
      }
      if (result.data.status === 'failed') {
        return {
          success: false,
          code: result.data.code,
          error: result.data.message,
        };
      }

      return {success: false, error: 'The psst passkey request expired'};
    }

    return {success: false, error: 'The psst passkey request was canceled'};
  } finally {
    await cancel(request.requestId, capability);
  }
};
