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
