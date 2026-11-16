import * as z from 'zod/mini';

export const NATIVE_HOST = 'com.evanpurkhiser.psst';

export const events = {
  request: 'psst-passkey-request',
  response: 'psst-passkey-response',
  cancel: 'psst-passkey-cancel',
  proxyReady: 'psst-passkey-proxy-ready',
  proxySettled: 'psst-passkey-proxy-settled',
  fallback: 'psst-passkey-fallback',
} as const;

export const passkeyRequestSchema = z.object({
  challenge: z.string(),
  rpId: z.string(),
  allowCredentials: z.array(z.string()),
});
export type PasskeyRequest = z.infer<typeof passkeyRequestSchema>;

const armMessageSchema = z.object({
  type: z.literal('psst.webauthn.arm'),
  requestId: z.string(),
  request: passkeyRequestSchema,
});
const cancelMessageSchema = z.object({
  type: z.literal('psst.webauthn.cancel'),
  requestId: z.string(),
});
export const backgroundMessageSchema = z.discriminatedUnion('type', [
  armMessageSchema,
  cancelMessageSchema,
]);
export type ArmMessage = z.infer<typeof armMessageSchema>;
export type CancelMessage = z.infer<typeof cancelMessageSchema>;

const failureSchema = z.object({
  success: z.literal(false),
  code: z.optional(z.string()),
  error: z.string(),
});
export const backgroundResponseSchema = z.union([
  z.object({success: z.literal(true), code: z.optional(z.literal('proxy_ready'))}),
  failureSchema,
]);
export type BackgroundResponse = z.infer<typeof backgroundResponseSchema>;

export interface AssertionRequest extends PasskeyRequest {
  requestId: string;
  origin: string;
}

export const assertionResponseSchema = z.union([
  z.object({success: z.literal(true), assertion: z.record(z.string(), z.unknown())}),
  failureSchema,
]);
export type AssertionResponse = z.infer<typeof assertionResponseSchema>;

export const relayResponseSchema = z.union([
  assertionResponseSchema,
  z.object({code: z.literal('use_browser')}),
]);
export type RelayResponse = z.infer<typeof relayResponseSchema>;
