---
layout: default
title: Release process
description: How to cut a semver release — images on GHCR, Helm OCI chart, GitHub Release
---

# Release process

One contributor, one command: **tag and push**. CI does the rest.

## Cut a release

```bash
# from main, after the change set you want shipped
git pull origin main
git tag v0.2.0
git push origin v0.2.0
```

Use [semver](https://semver.org/): `vMAJOR.MINOR.PATCH`. Optional prereleases (`v0.2.0-rc.1`) are marked as GitHub prereleases.

That triggers [`.github/workflows/release.yml`](../.github/workflows/release.yml), which:

1. Creates a **GitHub Release** (auto-generated notes)
2. Builds `linux/amd64` images and pushes to GHCR
3. Packages the Helm chart (`version` + `appVersion` = tag without `v`) and pushes it to OCI
4. Attaches the chart `.tgz` to the GitHub Release

## What gets published

| Artifact | Location |
|----------|----------|
| Backend | `ghcr.io/daimoniac/suppline:<version>` and `daimon666/suppline:<version>` (+ `X.Y`, `X`, `latest`) |
| UI | `ghcr.io/daimoniac/suppline-ui:<version>` and `daimon666/suppline-ui:<version>` |
| Trivy | upstream `aquasec/trivy` (Compose + Helm) — not rebuilt |
| Helm chart | `oci://ghcr.io/daimoniac/charts/suppline` (version = release) |

Requires repo secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` (Hub access token) so the release job can mirror images to Docker Hub after GHCR publish.

Install a released chart:

```bash
helm upgrade --install suppline oci://ghcr.io/daimoniac/charts/suppline \
  --version 0.2.0 \
  -n suppline --create-namespace \
  -f values-secrets.yaml
```

Empty image tags in the chart default to `Chart.AppVersion`, so a released chart pulls matching image tags.

## Verify with kind

Local smoke of a published chart (bundled lab registry, no PVCs). Needs `kind`, `kubectl`, `helm`, and `cosign`.

```bash
kind create cluster --name suppline-smoke
kubectl config use-context kind-suppline-smoke

rm -rf /tmp/suppline-smoke-keys && mkdir -p /tmp/suppline-smoke-keys
(cd /tmp/suppline-smoke-keys && COSIGN_PASSWORD=demo cosign generate-key-pair)
KEY_B64=$(base64 -w0 /tmp/suppline-smoke-keys/cosign.key)

helm upgrade --install suppline-smoke oci://ghcr.io/daimoniac/charts/suppline \
  --version 0.1.3 \
  -n suppline-smoke --create-namespace \
  --set registry.enabled=true \
  --set backend.secrets.SUPPLINE_API_KEY=demo \
  --set backend.secrets.ATTESTATION_KEY="$KEY_B64" \
  --set backend.secrets.ATTESTATION_KEY_PASSWORD=demo \
  --set persistence.data.enabled=false \
  --set persistence.trivyCache.enabled=false \
  --set registry.persistence.enabled=false \
  --wait --timeout 8m

kubectl get pods -n suppline-smoke
kubectl exec -n suppline-smoke suppline-smoke-0 -c suppline -- \
  wget -qO- http://localhost:8081/health

kubectl -n suppline-smoke port-forward svc/suppline-smoke-ui 3000:80
# http://localhost:3000 — API key: demo
```

Bump `--version` to the tag you just cut. Attestation signing still needs a key (throwaway is fine for this smoke). `registry.enabled=true` is lab-only — production stays bring-your-own registry.

Cleanup:

```bash
helm uninstall suppline-smoke -n suppline-smoke
kind delete cluster --name suppline-smoke
```

If GHCR pulls fail, set the packages to **Public** or `docker login ghcr.io` first.

## CI vs release

| Event | Workflow | Behavior |
|-------|----------|----------|
| PR / push to `main` | `docker-build.yml` | Build (PR) or push `main` / SHA tags (amd64 only) |
| PR / push touching chart | `helm.yml` | Lint + `helm template` smoke |
| Tag `v*` | `release.yml` | Semver images (amd64) + OCI chart + GitHub Release |

Do **not** hand-push release tags to GHCR; the tag workflow is the source of truth.

## First-time / visibility

GHCR packages for a public repo should be set to **Public** (package settings) so anonymous `docker pull` / `helm pull` work.

## Versioning tips (solo)

- **Patch** (`v0.2.1`): fixes, docs that affect install
- **Minor** (`v0.3.0`): features, chart value changes that stay compatible
- **Major** (`v1.0.0`): breaking API / chart / config changes

Bump only by choosing the next tag — you do not need to edit `Chart.yaml` version in git before tagging (the release job rewrites it for the published package).
