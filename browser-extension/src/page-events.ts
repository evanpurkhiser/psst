import * as z from 'zod/mini';

import {events, passkeyRequestSchema, relayResponseSchema} from './protocol';

const identifierSchema = z.object({id: z.string()});
const schemas = {
  [events.request]: z.object({id: z.string(), request: passkeyRequestSchema}),
  [events.response]: z.object({id: z.string(), response: relayResponseSchema}),
  [events.cancel]: identifierSchema,
  [events.proxyReady]: identifierSchema,
  [events.proxySettled]: z.object({
    id: z.string(),
    success: z.boolean(),
    error: z.optional(z.string()),
  }),
  [events.fallback]: identifierSchema,
};

type EventName = keyof typeof schemas;
type EventDetail<Name extends EventName> = z.infer<(typeof schemas)[Name]>;

/**
 * Shares one visible relay between the top page and its same-origin frames.
 */
export const pageEventTarget = (current: Window = window): Window | undefined => {
  const top = current.top;
  if (!top) {
    return current;
  }

  try {
    void top.location.href;
    return top;
  } catch {
    return undefined;
  }
};

export const dispatchPageEvent = <Name extends EventName>(
  name: Name,
  detail: EventDetail<Name>,
) => {
  const target = pageEventTarget();
  return target?.dispatchEvent(new CustomEvent(name, {detail})) ?? false;
};

export const listenForPageEvent = <Name extends EventName>(
  name: Name,
  listener: (detail: EventDetail<Name>) => void,
) => {
  pageEventTarget()?.addEventListener(name, event => {
    const parsed = z.safeParse(schemas[name], (event as CustomEvent<unknown>).detail);
    if (parsed.success) {
      listener(parsed.data as EventDetail<Name>);
    }
  });
};
