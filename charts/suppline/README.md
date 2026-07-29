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
- PersistentVolume support if `persistence.data.enabled` (SQLite state)
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

Images default to `ghcr.io/daimoniac/suppline` / `suppline-ui`; empty tags use `Chart.AppVersion`. Releases: [docs/RELEASE.md](../../docs/RELEASE.md).

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
      x-policy:
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

Data PVCs may be retained (`helm.sh/resource-policy: keep`) so reinstalls can reuse SQLite state.

## Configuration reference

| Parameter | Description | Default |
|-----------|-------------|---------|
| `backend.image.repository` | Backend image | `ghcr.io/daimoniac/suppline` |
| `backend.image.tag` | Backend tag | `""` → `Chart.AppVersion` |
| `backend.supplineConfig` | Inline `suppline.yml` (overrides chart file) | unset (use chart `suppline.yml`) |
| `backend.attestationKey.enabled` | Sign attestations | `true` |
| `backend.secrets.*` | API key, cosign key, registry creds | via secrets file |
| `frontend.enabled` | Deploy web UI | `true` |
| `frontend.image.repository` | UI image | `ghcr.io/daimoniac/suppline-ui` |
| `frontend.image.tag` | UI tag | `""` → `Chart.AppVersion` |
| `frontend.ingress.enabled` | UI Ingress | `false` |
| `regsync.enabled` | Deploy regsync | `true` |
| `registry.enabled` | Bundled registry | `false` (BYO) |
| `persistence.data.enabled` | SQLite PVC | `true` |
| `trivy.image.tag` | Trivy sidecar | `0.72.0` |

See `values.yaml` for the full set.

## After install

1. Port-forward or open Ingress to the UI; log in with `SUPPLINE_API_KEY`
2. Confirm sync targets appear and scans complete
3. Fetch admission policy: `GET /api/v1/integration/kyverno/policy`
4. Apply Kyverno/OPA in Audit, then Enforce

## Notes

- Backend uses SQLite → single replica (`ReadWriteOnce`)
- Chart ships an **example** `suppline.yml`, not a production site config
- OCI chart: `oci://ghcr.io/daimoniac/charts/suppline` — cut releases with [docs/RELEASE.md](../../docs/RELEASE.md)

## Support

https://github.com/daimoniac/suppline
