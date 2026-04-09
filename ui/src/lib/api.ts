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

      // Some write endpoints intentionally return 204 No Content.
      if (response.status === 204) {
        return { data: undefined as T, response };
      }

      const raw = await response.text();
      if (!raw) {
        return { data: undefined as T, response };
      }

      let data: T;
      try {
        data = JSON.parse(raw) as T;
      } catch {
        throw new APIError('Invalid JSON response', response.status, raw);
      }

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

  // VEX Statements
  async getVEXStatements(filters: Record<string, unknown> = {}) {
    return this.request<VEXSummary[]>(`/api/v1/vex${this.qs(filters)}`);
  }
  async getInactiveVEXStatements() {
    return this.request<VEXSummary[]>('/api/v1/vex/inactive');
  }

  // Policy
  async reevaluatePolicy(repository: string) {
    return this.request<{ message: string }>('/api/v1/policy/reevaluate', { method: 'POST', body: JSON.stringify({ repository }) });
  }

  // Integration
  async getKubernetesClusters() {
    return this.request<KubernetesClusterSummary[]>('/api/v1/integration/kubernetes/clusters');
  }
  async getKubernetesClusterImages(name: string) {
    return this.request<KubernetesClusterImageSummary[]>(`/api/v1/integration/kubernetes/clusters/${encodeURIComponent(name)}/images`);
  }
  async deleteKubernetesCluster(name: string) {
    return this.request<void>(`/api/v1/integration/kubernetes/clusters/${encodeURIComponent(name)}`, { method: 'DELETE' });
  }
  async getPublicKey() { return this.requestText('/api/v1/integration/publickey'); }
  async getKyvernoPolicy() { return this.requestText('/api/v1/integration/kyverno/policy'); }

  // Tasks
  async getSemverUpdateTasks(): Promise<SemverUpdateTasksResponse> {
    return this.request<SemverUpdateTasksResponse>('/api/v1/tasks/semver-updates');
  }
  async getVEXExpiryTasks(): Promise<VEXExpiryTasksResponse> {
    return this.request<VEXExpiryTasksResponse>('/api/v1/tasks/vex-expiry');
  }
  async getRuntimeUnusedWhitelist(): Promise<RuntimeUnusedWhitelistResponse> {
    return this.request<RuntimeUnusedWhitelistResponse>('/api/v1/tasks/runtime-unused-whitelist');
  }
  async addRuntimeUnusedWhitelist(repository: string): Promise<void> {
    await this.request('/api/v1/tasks/runtime-unused-whitelist', {
      method: 'POST',
      body: JSON.stringify({ repository }),
    });
  }
  async removeRuntimeUnusedWhitelist(repository: string): Promise<void> {
    await this.request('/api/v1/tasks/runtime-unused-whitelist', {
      method: 'DELETE',
      body: JSON.stringify({ repository }),
    });
  }

  // Health
  async getHealth() { return this.request<Record<string, unknown>>('/health'); }
}

// Types
export interface RuntimeImage {
  ImageRef: string;
  Tag: string;
  Digest: string;
}

export type RuntimeInventory = Record<string, Record<string, RuntimeImage[]>>;

export interface Scan {
  Digest: string;
  Repository: string;
  Tag: string;
  CreatedAt: number;
  ScannedAt?: number;
  PolicyPassed: boolean;
  PolicyStatus?: string; // "passed", "failed", or "pending"
  PolicyReason?: string;
  ReleaseAgeSeconds?: number;
  MinimumReleaseAgeSeconds?: number;
  ReleaseAgeSource?: string; // "image_created_at", "first_seen", or empty if unknown
  CriticalVulnCount: number;
  HighVulnCount: number;
  MediumVulnCount: number;
  LowVulnCount: number;
  SBOMAttested: boolean;
  VulnAttested: boolean;
  RuntimeUsed?: boolean;
  Runtime?: RuntimeInventory;
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

export interface AppliedVEXStatement {
  CVEID: string;
  State: string;
  Justification: string;
  Detail: string;
  AppliedAt: number;
  ExpiresAt: number;
}

export interface ScanDetail extends Scan {
  Vulnerabilities: Vulnerability[];
  AppliedVEXStatements: AppliedVEXStatement[];
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
  Exempted: number;
}

export interface Repository {
  Name: string;
  ArtifactCount: number;
  LastScanTime: number;
  PolicyPassed: boolean;
  PolicyStatus?: string;
  VulnerabilityCount: VulnCount;
  RuntimeUsed?: boolean;
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
  PolicyStatus?: string; // "passed", "failed", or "pending"
  PolicyReason?: string;
  ReleaseAgeSeconds?: number;
  MinimumReleaseAgeSeconds?: number;
  ReleaseAgeSource?: string; // "image_created_at", "first_seen", or empty if unknown
  ScanError: string;
  VulnerabilityCount: VulnCount;
  RuntimeUsed?: boolean;
  Runtime?: RuntimeInventory;
}

export interface RepositoryDetailResponse {
  Tags: RepositoryTag[];
  Total: number;
}

export interface RepositoryVEXInfo {
  Repository: string;
  AppliedAt: number;
}

export interface VEXSummary {
  CVEID: string;
  State: string;
  Justification: string;
  Detail: string;
  ExpiresAt: number;
  Repositories: RepositoryVEXInfo[];
  AffectedImageCount: number;
}

export interface KubernetesClusterSummary {
  Name: string;
  LastReported?: number;
  ImageCount: number;
}

export interface KubernetesClusterImageSummary {
  Namespace: string;
  ImageRef: string;
  Tag: string;
  Digest: string;
}

export interface SemverUpdateEntry {
  source: string;
  target: string;
  current_ranges: string[];
  runtime_versions: string[];
  out_of_range_versions: string[];
  suggested_ranges: string[] | null;
  /** "current" | "out_of_bounds" | "tighten" | "no_runtime_data" */
  status: string;
}

export interface SemverUpdateTasksResponse {
  entries: SemverUpdateEntry[];
  ai_agent_prompt: string;
  no_runtime_data: boolean;
}

export interface VEXExpiryTaskEntry {
  cve_id: string;
  repositories: string[];
  expires_at: number;
  state: string;
  justification: string;
  detail: string;
  /** "expired" | "expiring_soon" */
  status: string;
}

export interface VEXExpiryTasksResponse {
  entries: VEXExpiryTaskEntry[];
  ai_agent_prompt: string;
}

export interface RuntimeUnusedWhitelistResponse {
  repositories: string[];
}
