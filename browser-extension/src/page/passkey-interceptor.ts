import type {PasskeyRequest, RelayResponse} from '../protocol';

import {serializePasskeyRequest} from './passkey-request';

interface Subscriber {
  resolve(credential: Credential | null): void;
  reject(error: unknown): void;
  signal?: AbortSignal;
  abort(): void;
}

interface Operation {
  id: string;
  key: string;
  options: CredentialRequestOptions;
  container: CredentialsContainer;
  controller: AbortController;
  subscribers: Set<Subscriber>;
  started: boolean;
  attempt: number;
}

interface PasskeyInterceptorDependencies {
  invokeNative(
    container: CredentialsContainer,
    options: CredentialRequestOptions,
  ): Promise<Credential | null>;
  createId(): string;
  requestProxy(id: string, request: PasskeyRequest): void;
  cancelProxy(id: string): void;
  settleProxy(id: string, success: boolean, error?: string): void;
}

/**
 * Coordinates intercepted WebAuthn calls independently from browser transport.
 */
export const createPasskeyInterceptor = ({
  invokeNative,
  createId,
  requestProxy,
  cancelProxy,
  settleProxy,
}: PasskeyInterceptorDependencies) => {
  const pending = new Map<string, Operation>();

  const rejectAll = (operation: Operation, error: unknown) => {
    pending.delete(operation.key);
    for (const subscriber of operation.subscribers) {
      subscriber.signal?.removeEventListener('abort', subscriber.abort);
      subscriber.reject(error);
    }
    operation.subscribers.clear();
  };

  const resolveAll = (operation: Operation, credential: Credential | null) => {
    pending.delete(operation.key);
    for (const subscriber of operation.subscribers) {
      subscriber.signal?.removeEventListener('abort', subscriber.abort);
      subscriber.resolve(credential);
    }
    operation.subscribers.clear();
  };

  const runNative = (operation: Operation) => {
    if (operation.started) {
      return;
    }
    operation.started = true;
    const attempt = ++operation.attempt;
    const options = {...operation.options, signal: operation.controller.signal};

    invokeNative(operation.container, options).then(
      credential => {
        if (attempt !== operation.attempt) {
          return;
        }
        resolveAll(operation, credential);
        settleProxy(operation.id, true);
      },
      (error: unknown) => {
        if (attempt !== operation.attempt) {
          return;
        }
        rejectAll(operation, error);
        settleProxy(
          operation.id,
          false,
          error instanceof Error ? error.message : undefined,
        );
      },
    );
  };

  const findOperation = (id: string) =>
    [...pending.values()].find(operation => operation.id === id);

  const handleResponse = (id: string, response: RelayResponse) => {
    const operation = findOperation(id);
    if (!operation) {
      return;
    }
    if ('code' in response && response.code === 'use_browser') {
      operation.controller = new AbortController();
      operation.started = false;
      runNative(operation);
      return;
    }
    if ('success' in response && !response.success) {
      rejectAll(
        operation,
        new DOMException(
          response.error ?? 'psst passkey signing failed',
          'NotAllowedError',
        ),
      );
    }
  };

  const handleProxyReady = (id: string) => {
    const operation = findOperation(id);
    if (operation) {
      runNative(operation);
    }
  };

  const handleFallback = (id: string) => {
    const operation = findOperation(id);
    if (!operation || !operation.started) {
      return;
    }

    operation.attempt++;
    operation.started = false;
    operation.controller.abort();
  };

  const subscribe = (operation: Operation, signal?: AbortSignal) =>
    new Promise<Credential | null>((resolve, reject) => {
      const abort = () => {
        if (!operation.subscribers.delete(subscriber)) {
          return;
        }
        reject(new DOMException('The operation was aborted', 'AbortError'));
        if (operation.subscribers.size !== 0) {
          return;
        }

        pending.delete(operation.key);
        operation.attempt++;
        operation.controller.abort();
        cancelProxy(operation.id);
      };
      const subscriber: Subscriber = {resolve, reject, signal, abort};
      operation.subscribers.add(subscriber);

      if (signal?.aborted) {
        abort();
        return;
      }
      signal?.addEventListener('abort', abort, {once: true});
    });

  const intercept = (
    container: CredentialsContainer,
    options: CredentialRequestOptions,
  ) => {
    if (!options.publicKey || options.mediation === 'silent') {
      return invokeNative(container, options);
    }

    const request = serializePasskeyRequest(options.publicKey);
    const key = JSON.stringify(request);
    let operation = pending.get(key);
    if (!operation) {
      operation = {
        id: createId(),
        key,
        options,
        container,
        controller: new AbortController(),
        subscribers: new Set(),
        started: false,
        attempt: 0,
      };
      pending.set(key, operation);
      requestProxy(operation.id, request);
    }

    return subscribe(operation, options.signal);
  };

  return {intercept, handleResponse, handleProxyReady, handleFallback};
};
