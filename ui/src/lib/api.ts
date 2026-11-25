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

/** How long a GET keeps retrying 503 answers, e.g. during a PostgreSQL failover. */
const UNAVAILABLE_RETRY_BUDGET_MS = 60_000;
const UNAVAILABLE_RETRY_MAX_WAIT_MS = 15_000;

export class APIClient {
  private baseURL: string;
  private apiKey: string | null;
  private unauthorizedHandlers: Array<() => void> = [];
  private sleep: (ms: number) => Promise<void>;

  constructor(baseURL: string = '', sleep: (ms: number) => Promise<void> = ms => new Promise(r => setTimeout(r, ms))) {
    this.baseURL = baseURL;
    this.apiKey = null;
    this.sleep = sleep;
  }

  setAPIKey(key: string) { this.apiKey = key; }
  clearAPIKey() { this.apiKey = null; }
  getAPIKey() { return this.apiKey; }

  /** Register a callback for HTTP 401. Returns an unsubscribe function. */
  onUnauthorized(handler: () => void): () => void {
    this.unauthorizedHandlers.push(handler);
    return () => {
      this.unauthorizedHandlers = this.unauthorizedHandlers.filter(h => h !== handler);
    };
  }

  private notifyUnauthorized() {
    for (const h of this.unauthorizedHandlers) h();
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.apiKey) h['Authorization'] = `Bearer ${this.apiKey}`;
    return h;
  }

  private async request<T>(endpoint: string, opts: RequestInit = {}): Promise<T> {
    const { data } = await this.requestWithResponse<T>(endpoint, opts);
    return data;
  }

  private async requestWithResponse<T>(endpoint: string, opts: RequestInit = {}, retryCount = 0, unavailableWaitedMs = 0): Promise<{ data: T; response: Response }> {
    const url = `${this.baseURL}${endpoint}`;
    try {
      const response = await fetch(url, {
        method: 'GET',
        credentials: 'omit',
        ...opts,
        headers: { ...this.headers(), ...(opts.headers as Record<string, string> || {}) },
      });
      if (response.status === 401) {
        this.notifyUnauthorized();
        throw new APIError('Unauthorized', 401, 'Authentication required');
      }
      const method = (opts.method ?? 'GET').toUpperCase();
      if (response.status === 503 && method === 'GET' && unavailableWaitedMs < UNAVAILABLE_RETRY_BUDGET_MS) {
        // The server is briefly without its database or leader and says when
        // to come back. Only reads are repeated: a write may have been applied.
        const seconds = Number(response.headers.get('Retry-After'));
        const wait = Math.min(Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : 5000, UNAVAILABLE_RETRY_MAX_WAIT_MS);
        await this.sleep(wait);
        return this.requestWithResponse<T>(endpoint, opts, retryCount, unavailableWaitedMs + wait);
      }
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
        await this.sleep(1000 * (retryCount + 1));
        return this.requestWithResponse<T>(endpoint, opts, retryCount + 1, unavailableWaitedMs);
      }
      throw error;
    }
  }

  private async requestText(endpoint: string): Promise<string> {
    const url = `${this.baseURL}${endpoint}`;
    const response = await fetch(url, { method: 'GET', credentials: 'omit', headers: this.headers() });
    if (response.status === 401) {
      this.notifyUnauthorized();
      throw new APIError('Unauthorized', 401, 'Authentication required');
    }
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
  /** Failed or pending images a cluster runs, including digests a tag has moved off (Superseded). */
  async getRunningPolicyFailures() {
    return this.request<Scan[]>('/api/v1/images/running-failures');
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

  // Policies
  async getPolicies() {
    return this.request<PoliciesResponse>('/api/v1/policies');
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
  async getCoverage() {
    return this.request<CoverageResponse>('/api/v1/coverage');
  }

  async getClusterInstances() {
    return this.request<ClusterInstancesResponse>('/api/v1/cluster/instances');
  }

  // VEX Statements
  async getVEXStatements(filters: Record<string, unknown> = {}) {
    return this.request<VEXSummary[]>(`/api/v1/vex${this.qs(filters)}`);
  }
  async getInactiveVEXStatements() {
    return this.request<VEXSummary[]>('/api/v1/vex/inactive');
  }
  async getTriageRuns(filters: Record<string, unknown> = {}) {
    return this.request<TriageRun[]>(`/api/v1/triage${this.qs(filters)}`);
  }
  async getTriageStatements() {
    return this.request<TriageStatement[]>('/api/v1/triage/statements');
  }
  async getTriageRepositories() {
    return this.request<TriageRepository[]>('/api/v1/triage/repositories');
  }
  async getTriageStatus() {
    return this.request<TriageStatus>('/api/v1/triage/status');
  }
  async resetTriageBudget() {
    return this.request<TriageBudget>('/api/v1/triage/budget/reset', { method: 'POST', body: '{}' });
  }

  async acceptTriage(statement: TriageAccept) {
    return this.request<TriageAcceptResult>('/api/v1/triage/accept', {
      method: 'POST',
      body: JSON.stringify(statement),
    });
  }
  async retryTriage(run: { Repository: string; CVEID: string }) {
    return this.request<TriageRunResult>('/api/v1/triage/retry', {
      method: 'POST',
      body: JSON.stringify(run),
    });
  }
  async queueTriage(images: TriageRunImage[]) {
    return this.request<TriageRunResult>('/api/v1/triage/run', {
      method: 'POST',
      body: JSON.stringify({ Images: images }),
    });
  }
  async getGitopsRepositories() {
    return this.request<GitopsRepository[]>('/api/v1/integration/gitops');
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
  async getConfigEdits(): Promise<ConfigEditStatus> {
    return this.request<ConfigEditStatus>('/api/v1/tasks/config-edits');
  }
  async getSemverUpdateTasks(): Promise<SemverUpdateTasksResponse> {
    return this.request<SemverUpdateTasksResponse>('/api/v1/tasks/semver-updates');
  }
  async applySemverUpdates(updates: Array<{ target: string; ranges: string[] }>): Promise<ConfigEditResult> {
    return this.request<ConfigEditResult>('/api/v1/tasks/semver-updates', {
      method: 'POST',
      body: JSON.stringify({ updates }),
    });
  }
  async removeSyncTargets(targets: string[]): Promise<ConfigEditResult> {
    return this.request<ConfigEditResult>('/api/v1/tasks/sync-removals', {
      method: 'POST',
      body: JSON.stringify({ targets }),
    });
  }
  async removeVEXStatements(ids: string[]): Promise<ConfigEditResult> {
    return this.request<ConfigEditResult>('/api/v1/tasks/vex-removals', {
      method: 'POST',
      body: JSON.stringify({ ids }),
    });
  }
  async getVEXExpiryTasks(): Promise<VEXExpiryTasksResponse> {
    return this.request<VEXExpiryTasksResponse>('/api/v1/tasks/vex-expiry');
  }
  async getIneffectiveVEX(): Promise<IneffectiveVEXResponse> {
    return this.request<IneffectiveVEXResponse>('/api/v1/tasks/ineffective-vex');
  }
  async removeIneffectiveVEX(statements: IneffectiveVEXRef[]): Promise<ConfigEditResult> {
    return this.request<ConfigEditResult>('/api/v1/tasks/ineffective-vex-removals', {
      method: 'POST',
      body: JSON.stringify({ statements }),
    });
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
  async getHealth() {
    return this.request<{ status: string; version?: string; mirrorEnabled?: boolean; maliciousEnabled?: boolean }>('/health');
  }

  // Malicious packages
  async getMalicious() {
    return this.request<MaliciousOverview>('/api/v1/malicious');
  }

  // Mirror
  async getMirror() {
    return this.request<MirrorOverview>('/api/v1/mirror');
  }
  async getMirrorImages(key: string, limit: number, offset: number) {
    const { data, response } = await this.requestWithResponse<MirrorImage[]>(
      `/api/v1/mirror/syncs/${encodeURIComponent(key)}/images${this.qs({ limit, offset })}`,
    );
    return { images: data ?? [], total: totalCount(response, data?.length ?? 0) };
  }
  async getMirrorTagDeletions(key: string, limit: number, offset: number) {
    const { data, response } = await this.requestWithResponse<MirrorDeletion[]>(
      `/api/v1/mirror/syncs/${encodeURIComponent(key)}/deletions${this.qs({ limit, offset })}`,
    );
    return { deletions: data ?? [], total: totalCount(response, data?.length ?? 0) };
  }
  async getHeldDigests() {
    return (await this.request<HeldDigest[] | null>('/api/v1/mirror/held')) ?? [];
  }
  async releaseCooldown(repository: string, digest: string, reason: string): Promise<ConfigEditResult> {
    return this.request<ConfigEditResult>('/api/v1/mirror/held/release', {
      method: 'POST',
      body: JSON.stringify({ repository, digest, reason }),
    });
  }
  async getMirrorHubDeletions(limit: number, offset: number) {
    const { data, response } = await this.requestWithResponse<MirrorDeletion[]>(
      `/api/v1/mirror/hub-deletions${this.qs({ limit, offset })}`,
    );
    return { deletions: data ?? [], total: totalCount(response, data?.length ?? 0) };
  }
}

function totalCount(response: Response, fallback: number): number {
  const total = parseInt(response.headers.get('X-Total-Count') || '', 10);
  return Number.isNaN(total) ? fallback : total;
}

// Types
export interface MirrorSync {
  Key: string;
  Source: string;
  Target: string;
  Type: string;
  Schedule: string;
  Status: string;
  FinishedAt?: number | null;
  Error: string;
  ImageCount: number;
  TagDeletionCount: number;
}

export interface MirrorOverview {
  Syncs: MirrorSync[] | null;
  HubDeletionCount: number;
  HubError: string;
}

export interface MirrorImage {
  Repository: string;
  Tag: string;
  LastSeen: number;
}

/** A digest the tag runway holds off its tags. */
export interface HeldDigest {
  Repository: string;
  Digest: string;
  Source: string;
  Tags: string[] | null;
  /** When suppline first saw the digest upstream (Unix seconds). */
  FirstSeen: number;
  /** The repository's cooldown; 0 means the digest only waits for its attestation. */
  CooldownSeconds: number;
  /** Cooldown left; 0 once it is over or released. */
  RemainingSeconds: number;
  Released: boolean;
  /** Latest scan's policy status; empty before the first scan. */
  PolicyStatus: string;
  PolicyReason?: string;
  ScannedAt?: number;
}

export interface MirrorDeletion {
  Repository: string;
  Tag: string;
  DeletedAt: number;
}

export interface RuntimeImage {
  ImageRef: string;
  Tag: string;
  Digest: string;
  /** Pod owners running this image, as "Kind/name". Reported by newer cluster agents. */
  Workloads?: string[];
}

export interface PolicyFailureFinding {
  /** CVE id, or the MAL id when Kind is "malicious". */
  CVEID: string;
  PackageName: string;
  /** "malicious" for the built-in malicious-package gate; absent for vulnerabilities. */
  Kind?: 'vulnerability' | 'malicious';
}

export type MaliciousCheckStatus = 'ok' | 'unavailable' | 'stale';

export interface MaliciousFinding {
  ID: string;
  Ecosystem: string;
  PackageName: string;
  Version: string;
  PURL: string;
  Summary: string;
  URL: string;
  /** True when a false_positive VEX statement covers the finding; it does not fail policy. */
  Exempted?: boolean;
}

/** Outcome of one scan's malicious-package check. */
export interface MaliciousCheck {
  Status: MaliciousCheckStatus;
  Commit: string;
  /** Unix seconds of the feed sync the check used; 0 when unavailable. */
  SnapshotAt: number;
  Findings: MaliciousFinding[] | null;
}

export interface MaliciousFeed {
  Status: MaliciousCheckStatus;
  Commit: string;
  SyncedAt: number | null;
  LastAttemptAt: number | null;
  LastDurationMs: number;
  LastError: string;
  SyncIntervalSeconds: number;
  StaleAfterSeconds: number;
  RepoURL: string;
  Ref: string;
  Block: boolean;
  Ecosystems: string[] | null;
  Entries: number;
  Packages: Record<string, number> | null;
}

export interface MaliciousCoverage {
  OK: number;
  Unavailable: number;
  Stale: number;
  Unchecked: number;
}

export interface MaliciousImage {
  Repository: string;
  Digest: string;
  Tags: string[] | null;
  ScannedAt: number;
  PolicyPassed: boolean;
  PolicyStatus: string;
  RuntimeUsed: boolean;
  /** Hand-written false_positive statements of this repository for its findings. */
  FalsePositives?: MaliciousStatement[] | null;
  Runtime?: RuntimeInventory | null;
  CheckStatus: MaliciousCheckStatus;
  Findings: MaliciousFinding[];
}

export interface MaliciousStatement {
  ID: string;
  Detail: string;
  ExpiresAt?: number | null;
}

export interface MaliciousOverview {
  Enabled: boolean;
  Feed: MaliciousFeed | null;
  Coverage: MaliciousCoverage;
  Images: MaliciousImage[];
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
  /** The SCAI attestation admission control (Kyverno/OPA) verifies. */
  SCAIAttested: boolean;
  /** Published only when the scan applied VEX exemptions. */
  VEXAttested: boolean;
  RuntimeUsed?: boolean;
  Runtime?: RuntimeInventory;
  PolicyFailureFindings?: PolicyFailureFinding[];
  /** Malicious-package check; null when the check was disabled or the scan predates it. */
  Malicious?: MaliciousCheck | null;
  /** True when the tag has moved off this digest while a cluster still runs it. */
  Superseded?: boolean;
  /** The tag's current digest when Superseded is true. */
  CurrentDigest?: string;
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
  PolicyExpression?: string;
  PolicyDescription?: string;
  VulnerabilityCount: VulnCount;
  RuntimeUsed?: boolean;
  Whitelisted?: boolean;
}

export interface RepositoriesResponse {
  Repositories: Repository[];
  Total: number;
}

export interface PolicyInfo {
  Expression: string;
  Description: string;
}

export interface PoliciesResponse {
  Default?: PolicyInfo | null;
  Repositories?: Record<string, PolicyInfo>;
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
  Whitelisted?: boolean;
}

export interface RepositoryDetailResponse {
  Name?: string;
  Tags: RepositoryTag[];
  Total: number;
  PolicyExpression?: string;
  PolicyDescription?: string;
}

export interface RepositoryVEXInfo {
  Repository: string;
  AppliedAt: number;
  Source?: string;
  /** This repository's own statement. Repositories can differ for one CVE. */
  State?: string;
  Justification?: string;
  ExpiresAt?: number;
}

export interface TriageEvidence {
  repo: string;
  path: string;
  line: number;
  quote: string;
  pattern?: string;
  commit?: string;
  grep_id?: string;
}

export interface TriageRepoSHA {
  name: string;
  sha: string;
}

export interface TriageStatus {
  Enabled: boolean;
  Mode?: string;
  OnlyInUse: boolean;
  Pending: number;
  Sessions?: TriageSession[];
  Queued?: TriageQueued[];
  BudgetUsed?: number;
  BudgetLimit?: number;
  BudgetExhausted?: boolean;
}

export interface TriageBudget {
  BudgetUsed: number;
  BudgetLimit: number;
  BudgetExhausted: boolean;
}

export interface TriageSession {
  SessionID: string;
  Repository: string;
  Image?: string;
  Phase?: string;
  CurrentCVE?: string;
  CVEs: TriageSessionCVE[];
}

export interface TriageSessionCVE {
  CVEID: string;
  Status: string;
}

export interface TriageQueued {
  Repository: string;
  CVEID: string;
  Image?: string;
}

export interface TriageAccept {
  Repository: string;
  CVEID: string;
  State: string;
  Justification?: string;
  Detail?: string;
  ExpiresAt?: number;
}

export interface TriageAcceptResult {
  CommitSHA?: string;
}

export interface TriageRunImage {
  Repository: string;
  Digest: string;
  Tag: string;
}

export interface TriageRunResult {
  Queued: number;
}

export interface GitopsRepository {
  Name: string;
  URL: string;
  Branch?: string;
  Roles: string[];
  Cloned: boolean;
  HeadSHA?: string;
  HeadAt?: number;
  LastSupplineSHA?: string;
  LastSupplineAt?: number;
}

export interface TriageRun {
  ID: number;
  Repository: string;
  CVEID: string;
  Verdict: string;
  Justification?: string;
  Confidence: number;
  Evidence?: TriageEvidence[];
  Reasoning?: string;
  Model?: string;
  RepoSHAs?: TriageRepoSHA[];
  Tokens: number;
  Status: string;
  CommitSHA?: string;
  SessionID?: string;
  /** State of the statement the run wrote, or would write in dry-run mode. Empty when it wrote nothing. */
  WrittenState?: string;
  CreatedAt: number;
  Superseded?: boolean;
}

export interface TriageStatement {
  CVEID: string;
  Repository: string;
  State: string;
  Justification?: string;
  Detail?: string;
  ExpiresAt: number;
  CreatedAt: number;
  TriagedAt: number;
  AffectedImageCount: number;
  Source: 'auto' | 'manual' | 'open';
  NeedsFix: boolean;
  Run?: TriageRun;
}

/** 'manual' is a malicious-package finding: never triaged automatically, decided by a person. */
export type TriagePhase = 'manual' | 'uncertain' | 'error' | 'not_triaged' | 'running' | 'queued' | 'decided' | 'exempt';

export interface TriageRepositoryTag {
  Tag: string;
  Digest: string;
  PolicyPassed: boolean;
  PolicyStatus: string;
}

export interface TriageRepositoryCounts {
  Blocking: number;
  NeedsAttention: number;
  NotTriaged: number;
  Uncertain: number;
  Failed: number;
  InProgress: number;
  Decided: number;
  ExemptAuto: number;
  ExemptManual: number;
}

export interface TriageRepositoryCVE {
  CVEID: string;
  Phase: TriagePhase;
  /** A malicious-package advisory (MAL-*); only a hand-written false_positive exempts it. */
  Malicious?: boolean;
  Blocking: boolean;
  Packages?: string[];
  Tags: string[];
  Origin?: 'auto' | 'manual';
  State?: string;
  Justification?: string;
  Detail?: string;
  ExpiresAt?: number;
  Reason: string;
  ReasonCode?: 'exempt' | 'not_in_use' | 'not_in_scans' | 'cached' | 'budget';
  ReasonAt?: number;
  Run?: TriageRun;
}

export interface TriageRepository {
  Repository: string;
  PolicyPassed: boolean;
  Tags: TriageRepositoryTag[];
  Counts: TriageRepositoryCounts;
  CVEs: TriageRepositoryCVE[];
}

/** One CVE across repositories. The top-level statement fields are the first repository's by name; read each repository's own from Repositories. */
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

/** A running suppline instance; the leader runs the workers. */
export interface ClusterInstance {
  Hostname: string;
  Address: string;
  Version: string;
  Leader: boolean;
  /** The instance's own /health verdict at its last heartbeat. */
  Status: string;
  /** Status is healthy and the last heartbeat is under 30 s old. */
  Healthy: boolean;
  StartedAt: number;
  SeenAt: number;
}

export interface ClusterInstancesResponse {
  Instances: ClusterInstance[];
}

export interface CoverageResponse {
  Clusters: KubernetesClusterSummary[];
  DueForRescanCount: number;
  RescanIntervalSeconds: number;
  DigestCount: number;
  InUseDigestCount: number;
  StaleAfterSeconds: number;
  StaleClusterCount: number;
}

export interface KubernetesClusterImageSummary {
  Namespace: string;
  ImageRef: string;
  Tag: string;
  Digest: string;
}

export interface ConfigEditStatus {
  available: boolean;
  mode: string;
  detail?: string;
}

export interface ConfigEditResult {
  mode: string;
  commit?: string;
  updated: number;
  /** Repositories whose suppline state was removed although no sync entry named them any more. */
  cleaned?: number;
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

/** One repository's statement that is expired or expiring, with the facts that decide its actions. */
export interface VEXExpiryTaskEntry {
  cve_id: string;
  repository: string;
  /** Holds repository alone; kept for older clients. */
  repositories: string[];
  expires_at: number;
  state: string;
  justification: string;
  detail: string;
  /** "expired" | "expiring_soon" */
  status: string;
  /** "vex" (hand-written) | "vex-auto" (written by triage) */
  source: string;
  /** The one sync-entry copy of this id, so it can be extended or removed alone. False for defaults.vex. */
  editable: boolean;
  /** A scanned tag of the repository still reports the CVE. */
  in_scans: boolean;
  affected_tags?: string[];
  /** Newest scanned tag that no longer reports the CVE, when newer than every tag that does. */
  fixed_tag?: string;
  /** Triage refuses to exempt the CVE because it is in the CISA KEV catalog. */
  kev?: boolean;
  last_run?: TriageRun;
}

export interface VEXExpiryTasksResponse {
  entries: VEXExpiryTaskEntry[];
  ai_agent_prompt: string;
  triage_enabled: boolean;
}

/** A sync-entry VEX statement that no current policy decision depends on. */
export interface IneffectiveVEXStatement {
  repository: string;
  cve_id: string;
  /** "vex" (hand-written) | "vex-auto" (triage-owned) */
  source: string;
  state: string;
  justification?: string;
  detail?: string;
  expires_at?: number;
  /** "no_effect" (removal changes no latest scan's result) | "shadowed_by_defaults" (defaults.vex has the same id and wins) */
  reason?: string;
}

export interface IneffectiveVEXResponse {
  statements: IneffectiveVEXStatement[];
  /** Unix seconds of the last finished audit; 0 when none has finished yet. */
  computed_at: number;
}

export interface IneffectiveVEXRef {
  repository: string;
  cve_id: string;
  source: string;
}

export interface RuntimeUnusedWhitelistResponse {
  repositories: string[];
}
