import { describe, expect, it } from 'vitest';
import { basePathFromBaseHref } from './basePath';

describe('basePathFromBaseHref', () => {
  it('treats a missing base element as the root', () => {
    expect(basePathFromBaseHref(null)).toBe('');
    expect(basePathFromBaseHref(undefined)).toBe('');
  });

  it('treats "/" as the root', () => {
    expect(basePathFromBaseHref('/')).toBe('');
  });

  it('strips the trailing slash from a prefix', () => {
    expect(basePathFromBaseHref('/suppline/')).toBe('/suppline');
    expect(basePathFromBaseHref('/tools/suppline/')).toBe('/tools/suppline');
  });

  it('accepts an absolute base URL', () => {
    expect(basePathFromBaseHref('https://example.com/suppline/')).toBe('/suppline');
  });
});
