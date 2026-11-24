import { describe, expect, it } from 'vitest';
import { parseImageRef } from './registry';

describe('parseImageRef', () => {
  it.each([
    ['hostingmaloonde/kong', 'docker.io', 'dockerhub', 'hostingmaloonde/kong'],
    ['memcached', 'docker.io', 'dockerhub', 'memcached'],
    ['docker.io/library/nginx', 'docker.io', 'dockerhub', 'nginx'],
    ['index.docker.io/bitnami/redis', 'index.docker.io', 'dockerhub', 'bitnami/redis'],
    ['registry-1.docker.io/library/postgres:16', 'registry-1.docker.io', 'dockerhub', 'postgres:16'],
    ['dhi.io/python', 'dhi.io', 'dockerhub', 'python'],
    ['registry.gitlab.com/cmd/dev/frontline', 'registry.gitlab.com', 'gitlab', 'cmd/dev/frontline'],
    ['ghcr.io/org/app', 'ghcr.io', 'github', 'org/app'],
    ['quay.io/prometheus/node-exporter', 'quay.io', 'redhat', 'prometheus/node-exporter'],
    ['europe-west3-docker.pkg.dev/proj/repo/img', 'europe-west3-docker.pkg.dev', 'gcp', 'proj/repo/img'],
    ['eu.gcr.io/proj/img', 'eu.gcr.io', 'gcp', 'proj/img'],
    ['acme.jfrog.io/docker/app', 'acme.jfrog.io', 'jfrog', 'docker/app'],
    ['123456789012.dkr.ecr.eu-central-1.amazonaws.com/app', '123456789012.dkr.ecr.eu-central-1.amazonaws.com', 'other', 'app'],
    ['myreg.azurecr.io/team/app', 'myreg.azurecr.io', 'other', 'team/app'],
    ['localhost:5000/app', 'localhost:5000', 'other', 'app'],
    ['localhost/app', 'localhost', 'other', 'app'],
    ['harbor.internal.example/proj/app', 'harbor.internal.example', 'other', 'proj/app'],
  ])('%s', (ref, host, kind, path) => {
    const parsed = parseImageRef(ref);
    expect(parsed.host).toBe(host);
    expect(parsed.registry.kind).toBe(kind);
    expect(parsed.path).toBe(path);
    expect(parsed.full).toBe(ref);
  });

  it('labels known and unknown registries', () => {
    expect(parseImageRef('hostingmaloonde/kong').registry.label).toBe('Docker Hub');
    expect(parseImageRef('myreg.azurecr.io/app').registry.label).toBe('Azure Container Registry');
    expect(parseImageRef('registry.example.com/app').registry.label).toBe('registry.example.com');
  });

  it('keeps a bare library segment and empty input intact', () => {
    expect(parseImageRef('library').path).toBe('library');
    expect(parseImageRef('').path).toBe('');
  });
});
