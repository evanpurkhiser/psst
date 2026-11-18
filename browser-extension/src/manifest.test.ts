import {describe, expect, it} from 'vitest';

import manifest from '../manifest.json';

describe('extension manifest', () => {
  it('declares the browser HTTP boundary', () => {
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.permissions).toEqual(['webAuthenticationProxy']);
    expect(manifest.host_permissions).toEqual(['http://host.containers.internal:7338/*']);
    expect(manifest.minimum_chrome_version).toBe('115');
    expect(manifest.content_scripts.map(script => script.world)).toEqual([
      'ISOLATED',
      'MAIN',
    ]);
    expect(manifest.content_scripts[1]).toMatchObject({
      all_frames: true,
      match_about_blank: true,
    });
  });
});
