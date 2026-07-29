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

## Later step 1 — Helm / Artifact Hub

- [ ] Cut a release with current chart metadata (`git tag vX.Y.Z && git push origin vX.Y.Z`) — see [RELEASE.md](RELEASE.md)
- [ ] Verify: `helm show chart oci://ghcr.io/daimoniac/charts/suppline --version X.Y.Z`
- [ ] Verify images: `ghcr.io/daimoniac/suppline:X.Y.Z` (and `-ui`)
- [ ] Ensure GHCR packages are **Public**
- [ ] Submit / sync to [Artifact Hub](https://artifacthub.io/) with keywords: image admission, cosign, trivy, regsync, supply chain, Kyverno
- Chart README leads with BYO registry for prod; links Compose eval as the try-before path

Canonical chart OCI path: **`oci://ghcr.io/daimoniac/charts/suppline`**

## Later step 2 — awesome-lists (one-shot PRs)

Only when the eval checklist in [EVAL.md](EVAL.md) is honest:

- Relevant `awesome-*` lists (Kubernetes security, supply chain, Sigstore-related)
- Short blurb: self-hosted mirror → scan → CEL gate → cosign attestations; not a SaaS scanner

No ongoing community management — one PR each, then stop.
