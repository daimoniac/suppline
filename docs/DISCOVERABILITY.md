---
layout: default
title: Discoverability backlog
description: Later-step listings for suppline once the zero-cred eval path is proven
---

# Discoverability backlog

Do these **after** the [eval quick start](EVAL.md) works for strangers (`docker compose up --build` → pass + fail + attestations). Listing a broken first run wastes the only inbound channel we want.

## Done in this phase

- GitHub README + topics aligned to the glue + attest positioning
- [suppline.cloud](https://suppline.cloud) SEO (title/description, eval page, sitemap via Jekyll)

## Later step 1 — Helm / Artifact Hub

- Ensure the chart packages cleanly from CI (already partly covered by Helm workflows)
- Publish OCI chart to GHCR (or preferred registry) with a stable version tag
- Submit / sync to [Artifact Hub](https://artifacthub.io/) with accurate keywords: image admission, cosign, trivy, regsync, supply chain, Kyverno
- Chart `README.md`: lead with BYO registry for prod; link eval Compose as the try-before path

## Later step 2 — awesome-lists (one-shot PRs)

Only when the eval checklist in [EVAL.md](EVAL.md) is honest:

- Relevant `awesome-*` lists (Kubernetes security, supply chain, Sigstore-related)
- Short blurb: self-hosted mirror → scan → CEL gate → cosign attestations; not a SaaS scanner

No ongoing community management — one PR each, then stop.
