---
layout: default
title: Eval quick start
description: Zero-credential Docker Compose eval for suppline — mirror, scan, gate, and attest in one afternoon
---

# Eval quick start

**Stop maintaining supply-chain glue** — mirror, scan, policy, and cosign attestations in one system, and admit only what passed.

This path is throwaway: checkout the repo, start Compose, watch one image **pass** (with attestations) and one **fail**. No registry credentials, no cosign setup, no editing config.

Production installs should **bring your own registry** (Helm). See [Private registry setup](REGISTRY.md) and the main [README](https://github.com/daimoniac/suppline#deploy).

## Used in production

[SocialHub](https://www.socialhub.io) runs suppline in production as the intake gate for third-party images — continuous mirror → Trivy scan → CEL policy → Sigstore attestations, with cluster admission verifying the verdict. Their CI is a fair reference for how the gate fits a real platform pipeline.

## Run it

```bash
git clone https://github.com/daimoniac/suppline.git && cd suppline
docker compose up --build -d
```

`--build` picks up the current tree (needed for HTTP demo-registry support). First boot pulls images and Trivy’s DB — give it a few minutes.

Then:

1. Open **http://localhost:3000**
2. Log in with API key **`demo`**
3. Wait until repositories `demo-pass` and `demo-fail` appear
4. Confirm **demo-pass** is policy-passed with attestations; **demo-fail** is blocked

API check:

```bash
curl -s http://localhost:8081/health
curl -s -H "Authorization: Bearer demo" http://localhost:8080/api/v1/scans | head
```

| Port | Service |
|------|---------|
| 3000 | Web UI (API key `demo`) |
| 8080 | REST API + Swagger |
| 8081 | Health |
| 5000 | Throwaway registry (localhost only) |
| 9090 | Metrics |
| 4954 | Trivy |

## What the demo does

| Piece | Behavior |
|-------|----------|
| Registry | Bundled `registry:2` over HTTP — **not** for production |
| Sources | `public.ecr.aws` (no auth). Docker Hub is optional via `.env` |
| Signing | Cosign keypair auto-generated into `./keys/demo` on first start (does not touch existing `./keys/cosign.*`) |
| Policies | Intentional demo CEL: `true` / `false` so pass+fail always show |
| API key | Fixed `demo` — local eval only |

Config lives in [`suppline.demo.yml`](https://github.com/daimoniac/suppline/blob/main/suppline.demo.yml).

## You’re done when

- [ ] UI loads with key `demo`
- [ ] `demo-pass` shows **passed** and attestations on the digest
- [ ] `demo-fail` shows **failed** with the demo failure message
- [ ] Attestation gate POC admits pass / denies fail:

```bash
docker compose --profile eval-gate run --rm eval-gate
# or on the host (needs cosign + jq):
./scripts/eval-attestation-gate.sh
```

- [ ] (Optional) Kyverno ClusterPolicy YAML: `curl -s -H "Authorization: Bearer demo" http://localhost:8080/api/v1/integration/kyverno/policy`

The gate POC verifies the SCAI signature with `./keys/demo/cosign.pub`, checks `validUntil`, and applies the same `scanStatus` allow-list as Kyverno (`passed` / `passed-with-exceptions`). It does **not** spin up a cluster — that is the lightweight proof that admission would accept `demo-pass` and reject `demo-fail`.

## Optional: Docker Hub sources

Demo defaults avoid Hub rate limits. To mirror Hub images later, create a `.env`:

```bash
DOCKER_USERNAME=your-user
DOCKER_PASSWORD=your-token
```

Then add Hub `creds` + `sync` entries (see `suppline.yml.example`). Compose loads `.env` when present.

**Note:** If your `.env` already sets `ATTESTATION_KEY` for a production install, the eval entrypoint still uses `./keys/demo` with password `demo` — it will not reuse that production key.

## Next: real clusters

1. Point `target:` at **your** registry (Harbor, ECR, ACR, …)
2. Replace demo policies with real CEL + VEX — [Policy guide](POLICY.md)
3. Deploy with Helm; keep or disable the bundled chart registry — [REGISTRY.md](REGISTRY.md)
4. Apply the generated Kyverno/OPA admission policy
5. Generate your own cosign keys — never reuse `./keys/demo` from this eval

## Discoverability (later)

Eval quality comes first. Publishing to Artifact Hub / awesome-lists is tracked in [DISCOVERABILITY.md](DISCOVERABILITY.md).
