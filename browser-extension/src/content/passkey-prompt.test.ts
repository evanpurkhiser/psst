// @vitest-environment happy-dom

import {afterEach, describe, expect, it, vi} from 'vitest';

import {showPasskeyPrompt} from './passkey-prompt';

afterEach(() => {
  document.documentElement.replaceChildren(document.head, document.body);
  vi.restoreAllMocks();
});

describe('passkey prompt', () => {
  it('exposes the handoff through semantic controls', async () => {
    const attachShadow = Element.prototype.attachShadow;
    vi.spyOn(Element.prototype, 'attachShadow').mockImplementation(
      function (this: Element, init) {
        return attachShadow.call(this, {...init, mode: 'open'});
      },
    );
    const continueWithoutPsst = vi.fn();
    const prompt = showPasskeyPrompt({
      origin: 'https://example.com',
      rpId: 'example.com',
      requestId: 'request-id',
      continueWithoutPsst,
    });

    const host = document.querySelector('psst-passkey-request');
    const shadow = host?.shadowRoot;
    expect(shadow?.querySelector('dialog')?.open).toBe(true);
    expect(shadow?.querySelector('label')?.textContent).toContain('Browser request ID');
    expect(shadow?.querySelector('input')?.value).toBe('request-id');

    prompt.showStatus('Connected');
    await Promise.resolve();
    expect(shadow?.querySelector('output')?.textContent).toBe('Connected');

    shadow?.querySelector('button')?.click();
    expect(continueWithoutPsst).toHaveBeenCalledOnce();

    prompt.close();
    expect(document.querySelector('psst-passkey-request')).toBeNull();
  });
});
