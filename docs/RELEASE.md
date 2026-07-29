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
2. Builds multi-arch (`amd64`/`arm64`) images and pushes to GHCR
3. Packages the Helm chart (`version` + `appVersion` = tag without `v`) and pushes it to OCI
4. Attaches the chart `.tgz` to the GitHub Release

## What gets published

| Artifact | Location |
|----------|----------|
| Backend | `ghcr.io/daimoniac/suppline:<version>` and `daimon666/suppline:<version>` (+ `X.Y`, `X`, `latest`) |
| UI | `ghcr.io/daimoniac/suppline-ui:<version>` and `daimon666/suppline-ui:<version>` |
| Trivy | upstream `aquasec/trivy` (Compose + Helm) — not rebuilt |
| Helm chart | `oci://ghcr.io/daimoniac/charts/suppline` (version = release) |

Requires repo secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` (Hub access token) so the release job can mirror multi-arch manifests to Docker Hub after GHCR publish.

Install a released chart:

```bash
helm upgrade --install suppline oci://ghcr.io/daimoniac/charts/suppline \
  --version 0.2.0 \
  -n suppline --create-namespace \
  -f values-secrets.yaml
```

Empty image tags in the chart default to `Chart.AppVersion`, so a released chart pulls matching image tags.

## CI vs release

| Event | Workflow | Behavior |
|-------|----------|----------|
| PR / push to `main` | `docker-build.yml` | Build (PR) or push `main` / SHA tags (amd64 only) |
| PR / push touching chart | `helm.yml` | Lint + `helm template` smoke |
| Tag `v*` | `release.yml` | Semver images (multi-arch) + OCI chart + GitHub Release |

Do **not** hand-push release tags to GHCR; the tag workflow is the source of truth.

## First-time / visibility

GHCR packages for a public repo should be set to **Public** (package settings) so anonymous `docker pull` / `helm pull` work.

## Versioning tips (solo)

- **Patch** (`v0.2.1`): fixes, docs that affect install
- **Minor** (`v0.3.0`): features, chart value changes that stay compatible
- **Major** (`v1.0.0`): breaking API / chart / config changes

Bump only by choosing the next tag — you do not need to edit `Chart.yaml` version in git before tagging (the release job rewrites it for the published package).
