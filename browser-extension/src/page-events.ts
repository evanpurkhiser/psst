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

export const dispatchPageEvent = <Name extends EventName>(
  name: Name,
  detail: EventDetail<Name>,
) => window.dispatchEvent(new CustomEvent(name, {detail}));

export const listenForPageEvent = <Name extends EventName>(
  name: Name,
  listener: (detail: EventDetail<Name>) => void,
) => {
  window.addEventListener(name, event => {
    const parsed = z.safeParse(schemas[name], (event as CustomEvent<unknown>).detail);
    if (parsed.success) {
      listener(parsed.data as EventDetail<Name>);
    }
  });
};
