import {describe, expect, it} from 'vitest';

import manifest from '../manifest.json';

describe('extension manifest', () => {
  it('declares the native messaging boundary', () => {
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.permissions).toEqual(['nativeMessaging', 'webAuthenticationProxy']);
    expect(manifest.minimum_chrome_version).toBe('115');
    expect(manifest.content_scripts.map(script => script.world)).toEqual([
      'ISOLATED',
      'MAIN',
    ]);
  });
});
