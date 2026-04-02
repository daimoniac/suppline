export class APIError extends Error {
  status: number;
  details: string;
  constructor(message: string, status: number, details: string = '') {
    super(message);
    this.name = 'APIError';
    this.status = status;
    this.details = details;
  }
}

export class APIClient {
  private baseURL: string;
  private apiKey: string | null;

  constructor(baseURL: string = '') {
    this.baseURL = baseURL;
    this.apiKey = null;
  }

  setAPIKey(key: string) { this.apiKey = key; }
  clearAPIKey() { this.apiKey = null; }
  getAPIKey() { return this.apiKey; }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.apiKey) h['Authorization'] = `Bearer ${this.apiKey}`;
    return h;
  }

  private async request<T>(endpoint: string, opts: RequestInit = {}): Promise<T> {
    const { data } = await this.requestWithResponse<T>(endpoint, opts);
    return data;
  }

  private async requestWithResponse<T>(endpoint: string, opts: RequestInit = {}, retryCount = 0): Promise<{ data: T; response: Response }> {
    const url = `${this.baseURL}${endpoint}`;
    try {
      const response = await fetch(url, {
        method: 'GET',
        mode: 'cors',
        credentials: 'omit',
        ...opts,
        headers: { ...this.headers(), ...(opts.headers as Record<string, string> || {}) },
      });
      if (response.status === 401) throw new APIError('Unauthorized', 401, 'Authentication required');
      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new APIError(err.error || 'Request failed', response.status, err.details || response.statusText);
      }
      const data = await response.json() as T;
      return { data, response };
    } catch (error) {
      if (error instanceof TypeError && retryCount < 3) {
        await new Promise(r => setTimeout(r, 1000 * (retryCount + 1)));
        return this.requestWithResponse<T>(endpoint, opts, retryCount + 1);
      }
      throw error;
    }
  }

  private async requestText(endpoint: string): Promise<string> {
    const url = `${this.baseURL}${endpoint}`;
    const response = await fetch(url, { method: 'GET', mode: 'cors', credentials: 'omit', headers: this.headers() });
    if (!response.ok) throw new APIError('Request failed', response.status, response.statusText);
    return response.text();
  }

  private qs(filters: Record<string, unknown>): string {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') params.append(k, String(v));
    });
    const s = params.toString();
    return s ? '?' + s : '';
  }

  // Scans
  async getScans(filters: Record<string, unknown> = {}) {
    return this.request<Scan[]>(`/api/v1/scans${this.qs(filters)}`);
  }
  async getScansPage(filters: Record<string, unknown> = {}) {
    const { data, response } = await this.requestWithResponse<Scan[]>(`/api/v1/scans${this.qs(filters)}`);
    const total = parseInt(response.headers.get('X-Total-Count') || '0', 10);
    return { scans: data, total: Number.isNaN(total) ? data.length : total };
  }
  async getScanByDigest(digest: string) {
    return this.request<ScanDetail>(`/api/v1/scans/${encodeURIComponent(digest)}`);
  }
  async triggerScan(params: Record<string, string>) {
    return this.request<{ message: string; task_id?: string }>('/api/v1/scans/trigger', { method: 'POST', body: JSON.stringify(params) });
  }

  // Repositories
  async getRepositories(filters: Record<string, unknown> = {}) {
    return this.request<RepositoriesResponse>(`/api/v1/repositories${this.qs(filters)}`);
  }
  async getRepository(name: string, filters: Record<string, unknown> = {}) {
    return this.request<RepositoryDetailResponse>(`/api/v1/repositories/${encodeURIComponent(name)}${this.qs(filters)}`);
  }
  async triggerRepositoryRescan(name: string) {
    return this.request<{ message: string }>(`/api/v1/repositories/${encodeURIComponent(name)}/rescan`, { method: 'POST', body: '{}' });
  }
  async triggerTagRescan(name: string, tag: string) {
    return this.request<{ message: string }>(`/api/v1/repositories/${encodeURIComponent(name)}/tags/${encodeURIComponent(tag)}/rescan`, { method: 'POST', body: '{}' });
  }

  // Vulnerabilities
  async queryVulnerabilities(filters: Record<string, unknown> = {}) {
    const { data, response } = await this.requestWithResponse<VulnerabilityGroup[]>(`/api/v1/vulnerabilities${this.qs(filters)}`);
    const total = parseInt(response.headers.get('X-Total-Count') || '0', 10) || data.length;
    return { vulnerabilities: data, total };
  }
  async getVulnerabilityDetails(cveId: string, filters: Record<string, unknown> = {}) {
    return this.request<VulnerabilityGroup>(`/api/v1/vulnerabilities/${encodeURIComponent(cveId)}${this.qs(filters)}`);
  }
  async getVulnerabilityStats() {
    return this.request<Record<string, number>>('/api/v1/vulnerabilities/stats');
  }

  // Tolerations
  async getTolerations(filters: Record<string, unknown> = {}) {
    return this.request<Toleration[]>(`/api/v1/tolerations${this.qs(filters)}`);
  }
  async getInactiveTolerations() {
    return this.request<Toleration[]>('/api/v1/tolerations/inactive');
  }

  // Policy
  async reevaluatePolicy(repository: string) {
    return this.request<{ message: string }>('/api/v1/policy/reevaluate', { method: 'POST', body: JSON.stringify({ repository }) });
  }

  // Integration
  async getPublicKey() { return this.requestText('/api/v1/integration/publickey'); }
  async getKyvernoPolicy() { return this.requestText('/api/v1/integration/kyverno/policy'); }

  // Health
  async getHealth() { return this.request<Record<string, unknown>>('/health'); }
}

// Types
export interface Scan {
  Digest: string;
  Repository: string;
  Tag: string;
  CreatedAt: number;
  ScannedAt: number;
  PolicyPassed: boolean;
  CriticalVulnCount: number;
  HighVulnCount: number;
  MediumVulnCount: number;
  LowVulnCount: number;
  SBOMAttested: boolean;
  VulnAttested: boolean;
  RuntimeUsed?: boolean;
  RuntimeClusters?: string[];
  RuntimeNamespaces?: RuntimeLocation[];
}

export interface RuntimeLocation {
  Cluster: string;
  Namespace: string;
}

export interface Vulnerability {
  CVEID: string;
  Severity: string;
  PackageName: string;
  InstalledVersion: string;
  FixedVersion: string;
  Title: string;
  Description: string;
  PrimaryURL: string;
}

export interface ToleratedCVE {
  CVEID: string;
  Statement: string;
  ToleratedAt: number;
  ExpiresAt: number;
}

export interface ScanDetail extends Scan {
  Vulnerabilities: Vulnerability[];
  ToleratedCVEs: ToleratedCVE[];
  Tags: { Repository: string; Tag: string }[];
}

export interface VulnerabilityGroup {
  CVEID: string;
  Severity: string;
  Title: string;
  Description: string;
  PrimaryURL: string;
  affectedImageCount: number;
  affected: {
    repository: string;
    digests: {
      digest: string;
      tags: string[];
      packageName: string;
      installedVersion: string;
      fixedVersion: string;
      scannedAt: number;
      firstSeenAt: number;
    }[];
  }[];
}

export interface VulnCount {
  Critical: number;
  High: number;
  Medium: number;
  Low: number;
  Tolerated: number;
}

export interface Repository {
  Name: string;
  ArtifactCount: number;
  LastScanTime: number;
  PolicyPassed: boolean;
  VulnerabilityCount: VulnCount;
}

export interface RepositoriesResponse {
  Repositories: Repository[];
  Total: number;
}

export interface RepositoryTag {
  Name: string;
  Digest: string;
  LastScanTime: number;
  NextScanTime: number;
  PolicyPassed: boolean;
  ScanError: string;
  VulnerabilityCount: VulnCount;
}

export interface RepositoryDetailResponse {
  Tags: RepositoryTag[];
  Total: number;
}

export interface TolerationRepository {
  Repository: string;
  ToleratedAt: number;
}

export interface Toleration {
  CVEID: string;
  Statement: string;
  ExpiresAt: number;
  Repositories: TolerationRepository[];
}
