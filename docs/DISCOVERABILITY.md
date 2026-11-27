---
layout: default
title: Discoverability backlog
description: Later-step listings for suppline once the zero-cred eval path is proven
---

# Discoverability backlog

Do these **after** the [eval quick start](EVAL.md) works for strangers (`docker compose up --build` → pass + fail + attestations). Listing a broken first run wastes the only inbound channel we want.

## Done in this phase

- GitHub README + topics aligned to the glue + attest positioning
- [suppline.cloud](https://suppline.cloud) SEO (title/description, eval quick start, SocialHub reference)
- Helm chart BYO-registry defaults + example config in-repo
- Semver release pipeline (tag `v*` → GHCR images + OCI chart) — [RELEASE.md](RELEASE.md)

## Also done

- Pull-only eval: the release workflow generates `docker-compose.eval.yml` (`scripts/build-eval-compose.sh`) and attaches it to the GitHub Release; EVAL.md and the README lead with it
- [First cluster](FIRST_CLUSTER.md) page, [comparison](COMPARISON.md) page, and `values-lab.yaml` for a throwaway cluster
- Artifact Hub metadata in `charts/suppline/Chart.yaml` (category, license, links)

## Later step 1 — Helm / Artifact Hub

- [ ] Cut a release with current chart metadata (`git tag vX.Y.Z && git push origin vX.Y.Z`) — see [RELEASE.md](RELEASE.md)
- [ ] Verify: `helm show chart oci://ghcr.io/daimoniac/charts/suppline --version X.Y.Z`
- [ ] Verify images: `ghcr.io/daimoniac/suppline:X.Y.Z` (and `-ui`)
- [ ] Ensure GHCR packages are **Public**
- [ ] Verify the release attached `docker-compose.eval.yml` (the eval quick start links to `releases/latest/download/docker-compose.eval.yml`, which does not exist until a release ships it)
- [ ] Submit / sync to [Artifact Hub](https://artifacthub.io/) with keywords: image admission, cosign, trivy, regsync, supply chain, Kyverno
  - Add the OCI repository `oci://ghcr.io/daimoniac/charts/suppline` under Control Panel → Repositories (kind: Helm charts, OCI).
  - To claim ownership and get the verified badge, publish an `artifacthub-repo.yml` with your `repositoryID` to the same OCI path: `oras push ghcr.io/daimoniac/charts/suppline:artifacthub.io --config /dev/null:application/vnd.cncf.artifacthub.config.v1+yaml artifacthub-repo.yml:application/vnd.cncf.artifacthub.repository-metadata.layer.v1.yaml`
  - Optional: set `artifacthub.io/images` in `Chart.yaml` at release time so Artifact Hub shows the image security report
- Chart README leads with BYO registry for prod; links Compose eval as the try-before path

Canonical chart OCI path: **`oci://ghcr.io/daimoniac/charts/suppline`**

## Later step 2 — awesome-lists (one-shot PRs)

Only when the eval checklist in [EVAL.md](EVAL.md) is honest:

- Relevant `awesome-*` lists (Kubernetes security, supply chain, Sigstore-related)
- Short blurb: self-hosted mirror → scan → CEL gate → cosign attestations; not a SaaS scanner

No ongoing community management — one PR each, then stop.
