# Suppline Helm Chart

Production install path for [suppline](https://suppline.cloud) — self-hosted image intake gateway (mirror → scan → gate → attest).

**Try before you install:** zero-cred Compose eval — see [docs/EVAL.md](../../docs/EVAL.md).

## Packaging choice

Helm is the supported Kubernetes install. Raw manifests / Kustomize are not maintained as a second tree; generate them if needed:

```bash
helm template suppline ./charts/suppline \
  -f values.yaml -f values-secrets.yaml > manifests.yaml
```

## Prerequisites

- Kubernetes 1.19+
- Helm 3 or 4
- A **target registry you control** (Harbor, ECR, ACR, Artifactory, …) — preferred for production
- PersistentVolume for the bundled PostgreSQL (`postgres.enabled`, default); or bring your own with `backend.secrets.POSTGRES_URL`
- Cosign keypair for attestation signing

## Quick install (BYO registry)

From a published release:

```bash
helm upgrade --install suppline oci://ghcr.io/daimoniac/charts/suppline \
  --version <x.y.z> \
  -n suppline --create-namespace \
  -f values-secrets.yaml
```

From this repository:

```bash
cp charts/suppline/values-secrets.yaml.example charts/suppline/values-secrets.yaml
# Edit secrets: SUPPLINE_API_KEY, ATTESTATION_KEY*, SUPPLINE_REGISTRY_*, upstream creds
# Edit sync/policy: either charts/suppline/suppline.yml or backend.supplineConfig in values

helm upgrade --install suppline ./charts/suppline \
  -n suppline --create-namespace \
  -f charts/suppline/values.yaml \
  -f charts/suppline/values-secrets.yaml
```

Point `sync[].target` (and `creds`) at your registry. The chart example uses `{{ env "SUPPLINE_REGISTRY_URL" }}`.

The image defaults to `ghcr.io/daimoniac/suppline` (the web UI is built in); empty tags use `Chart.AppVersion`. Releases: [docs/RELEASE.md](../../docs/RELEASE.md).

### Override config without editing the chart

```yaml
# my-values.yaml
backend:
  supplineConfig: |
    version: 1
    creds:
      - registry: '{{ env "SUPPLINE_REGISTRY_URL" }}'
        user: '{{ env "SUPPLINE_REGISTRY_USERNAME" }}'
        pass: '{{ env "SUPPLINE_REGISTRY_PASSWORD" }}'
    defaults:
      policy:
        expression: "criticalCount == 0"
    sync:
      - source: public.ecr.aws/docker/library/alpine:3.20.3
        target: '{{ env "SUPPLINE_REGISTRY_URL" }}/alpine:3.20.3'
        type: image
```

## Bundled registry (optional / labs)

Default is `registry.enabled: false`. To bootstrap without an external registry:

```yaml
registry:
  enabled: true
```

Do **not** treat the bundled `registry:3` as a long-term production registry. Details: [docs/REGISTRY.md](../../docs/REGISTRY.md).

## Uninstall

```bash
helm uninstall suppline -n suppline
```

Data PVCs may be retained (`helm.sh/resource-policy: keep`) so reinstalls can reuse database volumes.

## Configuration reference

| Parameter | Description | Default |
|-----------|-------------|---------|
| `backend.replicaCount` | Instances. Above 1: one leader plus warm standbys that forward API traffic to it; adds a PDB (`minAvailable: 1`) and required pod anti-affinity | `1` |
| `backend.strategy` | Deployment update strategy. Required anti-affinity with `maxSurge: 1` needs `replicaCount + 1` nodes; otherwise use `maxSurge: 0, maxUnavailable: 1` | `RollingUpdate`, `maxSurge: 1`, `maxUnavailable: 0` |
| `backend.terminationGracePeriodSeconds` | Must exceed suppline's 60 s shutdown drain | `90` |
| `trivy.cacheSizeLimit` | Size limit of the per-pod Trivy cache `emptyDir` | `15Gi` |
| `backend.image.repository` | Backend image | `ghcr.io/daimoniac/suppline` |
| `backend.image.tag` | Backend tag | `""` → `Chart.AppVersion` |
| `backend.supplineConfig` | Inline `suppline.yml` (overrides chart file) | unset (use chart `suppline.yml`) |
| `backend.attestationKey.enabled` | Sign attestations | `true` |
| `backend.secrets.*` | API key, cosign key, registry creds | via secrets file |
| `ingress.enabled` | Ingress to the UI and API on the backend service; its path is `server.basePath` from suppline.yml | `false` |
| `ingress.hosts` | Host names for the ingress | `[suppline.example.com]` |
| `registry.enabled` | Bundled registry | `false` (BYO) |
| `postgres.enabled` | Bundled PostgreSQL; set `false` and `backend.secrets.POSTGRES_URL` for an external one | `true` |
| `backend.resources` | CPU/memory for the suppline container | `1Gi` request / `4Gi` limit (attestation spikes + page cache; not a heap leak) |
| `trivy.image.tag` | Trivy sidecar | `0.76.2` |

See `values.yaml` for the full set.

## After install

1. Port-forward or open Ingress to the UI; log in with `SUPPLINE_API_KEY`
2. Confirm sync targets appear and scans complete
3. Fetch admission policy: `GET /api/v1/integration/kyverno/policy` (Kyverno `ImageValidatingPolicy`)
4. Apply Kyverno/OPA in Audit, then Deny (`validationActions`)

## Notes

- Backend runs as a Deployment. With `backend.replicaCount` above 1, instances elect a leader through PostgreSQL and standbys forward the API and UI to it; see [ADR 0004](../../docs/adr/0004-warm-standby-with-postgres-leader-election.md). Pods must reach each other on the API port.
- Upgrading from a chart that ran a StatefulSet replaces it with a Deployment, with a short outage. Delete the leftover `trivy-cache-*` PVCs afterwards, if `persistence.trivyCache` was enabled.
- `/data` is an emptyDir: the malicious-packages feed is cloned again after each restart
- Chart ships an **example** `suppline.yml`, not a production site config
- OCI chart: `oci://ghcr.io/daimoniac/charts/suppline` — cut releases with [docs/RELEASE.md](../../docs/RELEASE.md)

## Support

https://github.com/daimoniac/suppline
