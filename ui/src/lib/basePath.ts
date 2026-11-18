/**
 * The URL path suppline is served under, without a trailing slash ("" at the
 * root). The backend injects <base href="{basePath}/"> into index.html; the
 * Vite dev server has no <base> element, so dev runs at the root.
 */
export function basePathFromBaseHref(href: string | null | undefined): string {
  if (!href) return '';
  return new URL(href, 'http://localhost').pathname.replace(/\/+$/, '');
}

export const basePath =
  typeof document === 'undefined'
    ? ''
    : basePathFromBaseHref(document.querySelector('base')?.getAttribute('href'));
