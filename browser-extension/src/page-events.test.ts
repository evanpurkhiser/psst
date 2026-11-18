// @vitest-environment happy-dom

import {describe, expect, it} from 'vitest';

import {pageEventTarget} from './page-events';

describe('page event target', () => {
  it('shares the top page with a same-origin child frame', () => {
    const top = {location: {href: 'https://example.com'}} as unknown as Window;
    const child = {top} as unknown as Window;

    expect(pageEventTarget(child)).toBe(top);
  });

  it('does not bridge a cross-origin child frame', () => {
    const top = {
      location: {
        get href(): string {
          throw new DOMException('Blocked', 'SecurityError');
        },
      },
    } as unknown as Window;
    const child = {top} as unknown as Window;

    expect(pageEventTarget(child)).toBeUndefined();
  });
});
