import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { KEVBadge } from './ui';

describe('KEVBadge', () => {
  it('renders nothing for an unlisted CVE', () => {
    expect(renderToStaticMarkup(<KEVBadge info={undefined} />)).toBe('');
    expect(renderToStaticMarkup(<KEVBadge info={null} />)).toBe('');
  });

  it('marks a listed CVE, with ransomware use and the dates in the tooltip', () => {
    const html = renderToStaticMarkup(<KEVBadge info={{ DateAdded: '2024-03-01', DueDate: '2024-03-22', Ransomware: true }} />);
    expect(html).toContain('Known exploited');
    expect(html).toContain('ransomware');
    expect(html).toContain('since 2024-03-01');
    expect(html).toContain('due 2024-03-22');
  });

  it('leaves out the ransomware note when CISA does not list it', () => {
    const html = renderToStaticMarkup(<KEVBadge info={{ DateAdded: '2023-11-21', DueDate: '', Ransomware: false }} />);
    expect(html).toContain('Known exploited');
    expect(html).not.toContain('· ransomware');
  });
});
