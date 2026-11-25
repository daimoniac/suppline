import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import type { ClusterInstance } from '../lib/api';
import { ClusterStateCard } from './ClusterStateCard';

const instance = (Hostname: string, Leader: boolean): ClusterInstance => ({
  Hostname, Leader, Address: 'http://10.0.0.1:8080', Version: 'abc', StartedAt: 0, SeenAt: 0,
});

describe('ClusterStateCard', () => {
  it('lists every instance and marks only the leader', () => {
    const html = renderToStaticMarkup(
      <ClusterStateCard instances={[instance('suppline-suppline-7896ff8d5f-5d8vd', true), instance('suppline-suppline-7896ff8d5f-q9mnh', false)]} />,
    );
    expect(html).toContain('Cluster state');
    expect(html).toContain('suppline-suppline-7896ff8d5f-5d8vd');
    expect(html).toContain('suppline-suppline-7896ff8d5f-q9mnh');
    expect(html.match(/data-leader="true"/g)).toHaveLength(1);
    expect(html).toMatch(/data-leader="true"[^>]*title="suppline-suppline-7896ff8d5f-5d8vd/);
    // Long hostnames keep their distinctive end: the ellipsis goes in front.
    expect(html).toContain('direction:rtl');
  });

  it('says when no instance reported', () => {
    expect(renderToStaticMarkup(<ClusterStateCard instances={[]} />)).toContain('No instance reported');
  });
});
