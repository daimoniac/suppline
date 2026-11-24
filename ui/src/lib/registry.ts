/**
 * Splits image references into registry host and repository path, and maps
 * the host to a known registry so the UI can show a short name plus an icon.
 */

export type RegistryKind =
  | 'dockerhub'
  | 'gitlab'
  | 'github'
  | 'redhat'
  | 'gcp'
  | 'jfrog'
  | 'gitea'
  | 'codeberg'
  | 'digitalocean'
  | 'other';

export interface RegistryInfo {
  kind: RegistryKind;
  /** Human-readable registry name for tooltips, e.g. "Docker Hub". */
  label: string;
}

export interface ParsedImageRef {
  /** The reference exactly as given. */
  full: string;
  /** Registry host; "docker.io" for implicit Docker Hub refs. */
  host: string;
  registry: RegistryInfo;
  /** Reference without the registry host (and without Docker Hub's "library/"). */
  path: string;
}

const DOCKER_HUB_HOSTS = new Set(['docker.io', 'index.docker.io', 'registry-1.docker.io', 'registry.hub.docker.com']);

const EXACT_HOSTS: Record<string, RegistryInfo> = {
  'dhi.io': { kind: 'dockerhub', label: 'Docker Hardened Images' },
  'registry.gitlab.com': { kind: 'gitlab', label: 'GitLab' },
  'gitlab.com': { kind: 'gitlab', label: 'GitLab' },
  'ghcr.io': { kind: 'github', label: 'GitHub Container Registry' },
  'docker.pkg.github.com': { kind: 'github', label: 'GitHub Packages' },
  'quay.io': { kind: 'redhat', label: 'Quay' },
  'registry.redhat.io': { kind: 'redhat', label: 'Red Hat' },
  'registry.access.redhat.com': { kind: 'redhat', label: 'Red Hat' },
  'gcr.io': { kind: 'gcp', label: 'Google Container Registry' },
  'codeberg.org': { kind: 'codeberg', label: 'Codeberg' },
  'gitea.com': { kind: 'gitea', label: 'Gitea' },
  'registry.digitalocean.com': { kind: 'digitalocean', label: 'DigitalOcean' },
  'public.ecr.aws': { kind: 'other', label: 'AWS ECR Public' },
  'mcr.microsoft.com': { kind: 'other', label: 'Microsoft Container Registry' },
};

const PATTERN_HOSTS: Array<{ pattern: RegExp; info: RegistryInfo }> = [
  { pattern: /^[^/]+-docker\.pkg\.dev$/, info: { kind: 'gcp', label: 'Google Artifact Registry' } },
  { pattern: /^[^/]+\.gcr\.io$/, info: { kind: 'gcp', label: 'Google Container Registry' } },
  { pattern: /^[^/]+\.jfrog\.io$/, info: { kind: 'jfrog', label: 'JFrog' } },
  { pattern: /^[^/]+\.dkr\.ecr\.[^/]+\.amazonaws\.com(\.cn)?$/, info: { kind: 'other', label: 'AWS ECR' } },
  { pattern: /^[^/]+\.azurecr\.io$/, info: { kind: 'other', label: 'Azure Container Registry' } },
];

/** Docker's rule: the first segment is a host if it has a dot or a port, or is "localhost". */
function isHostSegment(segment: string): boolean {
  return segment.includes('.') || segment.includes(':') || segment === 'localhost';
}

export function registryForHost(host: string): RegistryInfo {
  const h = host.toLowerCase();
  if (DOCKER_HUB_HOSTS.has(h)) return { kind: 'dockerhub', label: 'Docker Hub' };
  const exact = EXACT_HOSTS[h];
  if (exact) return exact;
  for (const { pattern, info } of PATTERN_HOSTS) {
    if (pattern.test(h)) return info;
  }
  return { kind: 'other', label: host };
}

export function parseImageRef(ref: string): ParsedImageRef {
  const full = ref ?? '';
  const trimmed = full.trim();
  const slash = trimmed.indexOf('/');
  const first = slash >= 0 ? trimmed.slice(0, slash) : '';

  let host = 'docker.io';
  let path = trimmed;
  if (slash >= 0 && isHostSegment(first)) {
    host = first;
    path = trimmed.slice(slash + 1);
  }

  const registry = registryForHost(host);
  if (DOCKER_HUB_HOSTS.has(host.toLowerCase()) && path.startsWith('library/') && path.length > 'library/'.length) {
    path = path.slice('library/'.length);
  }

  return { full, host, registry, path: path || trimmed };
}
