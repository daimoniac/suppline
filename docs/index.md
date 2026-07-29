---
layout: default
title: suppline - Self-hosted image intake gateway for Kubernetes
description: Self-hosted Kubernetes image intake gateway — mirror, Trivy scan, CEL policy gate, and Sigstore attestations. Replace regsync+scanner+admission glue; admit only what passed. Used in production at SocialHub.
---

# suppline

*Self-hosted image intake gateway for Kubernetes.*

**Mirror → Scan → Gate → Attest → Run.**

Stop maintaining supply-chain glue — mirror, scan, policy, and cosign attestations in one system, and admit only what passed.

Your cluster runs dozens of third-party images you didn't build. Every one is a pull from someone else's registry, on someone else's uptime, with a CVE list nobody has reviewed since the day it was deployed.

suppline is the gate in front of that. It continuously mirrors upstream images into **your** registry, scans every digest with Trivy, evaluates a policy you wrote, and publishes signed Sigstore attestations. Clusters then pull only from the mirror — and can refuse to run anything without a valid, fresh attestation.

One Go binary. SQLite state. No SaaS, no phone-home, air-gap compatible by design.

**[Try the zero-cred eval →](EVAL.md)** · [GitHub](https://github.com/daimoniac/suppline)

## Used in production

[SocialHub](https://www.socialhub.io) runs suppline in production to gate third-party images (mirror → scan → policy → attest) before admission.

## Why you might want this

- **Your cluster stops depending on Docker Hub.** Upstream outages, rate limits, and deleted tags no longer break a deploy.
- **Every third-party image gets reviewed — continuously.** Digests are rescanned on an interval, and new upstream tags enter the same gate automatically.
- **Policy is code, not a wiki page.** CEL expressions per repository, with expiring VEX exemptions instead of permanent tribal knowledge.
- **The verdict is cryptographic.** Kyverno or OPA verifies a cosign attestation at admission time, so the gate holds even if suppline is down.
- **You can answer the audit question.** Which images fail policy, which of those are actually running in production, and what was known at the time.

## How it works

![suppline supply chain workflow](suppline_workflow.jpg)

1. **Mirror** — regsync keeps your registry in sync with the upstream repositories listed in `suppline.yml`.
2. **Scan** — the watcher notices new or changed digests and enqueues them; Trivy produces an SBOM and vulnerability set.
3. **Gate** — active VEX statements are applied, then your CEL policy decides: `passed`, `failed`, or `pending`.
4. **Attest** — cosign signs SBOM, vulnerability, VEX, and SCAI attestations into the registry next to the image.
5. **Run** — clusters pull from the mirror; Kyverno/OPA verifies the SCAI attestation before a pod starts.

The full lifecycle, including rescan triggers and error paths, is documented in the [state machine reference](STATE_MACHINE.md).

## Quick start (eval)

No credentials required. Bundled throwaway registry; demo pass + fail policies.

```bash
git clone https://github.com/daimoniac/suppline.git && cd suppline
docker compose up --build -d
```

Open `http://localhost:3000` and log in with API key `demo`. Full checklist: [Eval quick start](EVAL.md).

## What you get

- **Continuous mirroring** into any private registry, or the one bundled with the Helm chart
- **Trivy scanning** with SBOM generation for every digest
- **CEL policy engine** with per-repository overrides and a minimum release age hold
- **Expiring VEX exemptions**, so accepted risks resurface instead of living forever
- **Sigstore attestations** — SBOM, vulnerability, VEX, and SCAI — signed with your own key
- **Kyverno policy generation** for verified-only admission, straight from the API
- **Runtime awareness** via an optional cluster agent, so you can tell a backlog item from an incident
- **REST API, web UI, MCP server** for LLM clients, Prometheus metrics, and structured JSON logs

## Documentation

- [Eval quick start](EVAL.md) — zero-cred Compose afternoon path
- [Configuration reference](CONFIGURATION.md) — every environment variable and `suppline.yml` field
- [Policy guide](POLICY.md) — CEL reference, policy recipes, VEX semantics
- [State machine](STATE_MACHINE.md) — image lifecycle, rescan triggers, error handling
- [Private registry setup](REGISTRY.md) — running the bundled registry in Kubernetes
- [Discoverability backlog](DISCOVERABILITY.md) — Artifact Hub / awesome-lists (later)
- [GitHub repository](https://github.com/daimoniac/suppline) — source, Helm chart, issues

## Support

Apache 2.0 licensed. Questions, bug reports, and feature ideas belong in [GitHub Issues](https://github.com/daimoniac/suppline/issues).
