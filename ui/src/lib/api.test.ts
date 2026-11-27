import { afterEach, describe, expect, it, vi } from 'vitest';
import { APIClient, APIError } from './api';

function reply(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

describe('APIClient during a database failover', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('retries a GET that got 503 after Retry-After, then returns the data', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(reply(503, { error: 'database briefly unavailable' }, { 'Retry-After': '1' }))
      .mockResolvedValueOnce(reply(200, { Clusters: [] }));
    vi.stubGlobal('fetch', fetchMock);
    const waits: number[] = [];
    const client = new APIClient('', async ms => { waits.push(ms); });

    await expect(client.getCoverage()).resolves.toEqual({ Clusters: [] });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(waits).toEqual([1000]);
  });

  it('gives up after about a minute of 503s', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => reply(503, { error: 'down' }, { 'Retry-After': '5' })));
    let waited = 0;
    const client = new APIClient('', async ms => { waited += ms; });

    await expect(client.getCoverage()).rejects.toMatchObject({ status: 503 });
    expect(waited).toBeGreaterThanOrEqual(55_000);
    expect(waited).toBeLessThanOrEqual(65_000);
  });

  it('does not repeat a write that got 503', async () => {
    const fetchMock = vi.fn(async () => reply(503, { error: 'down' }, { 'Retry-After': '1' }));
    vi.stubGlobal('fetch', fetchMock);
    const client = new APIClient('', async () => {});

    await expect(client.retryTriage({ Repository: 'r', CVEID: 'CVE-1' })).rejects.toBeInstanceOf(APIError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe('APIClient text endpoints', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('builds the mirror rewrite query and skips empty options', async () => {
    const fetchMock = vi.fn<(url: string) => Promise<Response>>(async () => new Response('kind: MutatingPolicy', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const client = new APIClient('', async () => {});

    await expect(client.getMirrorRewritePolicy({ mirror: '', registries: 'docker.io,ghcr.io', scope: 'all' })).resolves.toBe('kind: MutatingPolicy');
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/integration/kyverno/mirror-rewrite?registries=docker.io%2Cghcr.io&scope=all');
  });

  it('puts the server message from a JSON error body into details', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => reply(400, { error: 'mirror is required: pass ?mirror= or set SUPPLINE_REGISTRY_URL' })));
    const client = new APIClient('', async () => {});

    await expect(client.getMirrorRewritePolicy()).rejects.toMatchObject({
      status: 400,
      details: 'mirror is required: pass ?mirror= or set SUPPLINE_REGISTRY_URL',
    });
  });

  it('keeps the status text when the error body is not JSON', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('nope', { status: 500, statusText: 'Internal Server Error' })));
    const client = new APIClient('', async () => {});

    await expect(client.getKubernetesClusterMigration('prod a')).rejects.toMatchObject({ status: 500, details: 'Internal Server Error' });
  });
});
