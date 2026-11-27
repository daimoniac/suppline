---
layout: default
title: How suppline compares
description: suppline next to Trivy Operator, Harbor, Kyverno alone, and hand-built regsync + scanner glue
---

# How suppline compares

suppline is the gate in front of the third-party images your cluster runs. It does two things that scanners usually leave to someone else, and one that registries usually leave out:

1. **A mirror the cluster can pull from.** Docker Hub being down, rate-limiting you, or a tag being deleted stops breaking deploys.
2. **A signed verdict.** Each digest gets a cosign attestation saying whether it passed policy and until when. Kyverno or OPA checks it at admission, so the gate holds even if suppline itself is down.
3. **Continuous review, not an onboarding scan.** Digests are rescanned on an interval, new upstream tags enter the same gate, and a new CISA KEV listing re-opens it the same day.

If you already scan, the question is what happens *after* the scan: who copies the image, who decides, and what the cluster checks before it starts a pod.

## Next to what you may already run

| You run | It does | What suppline adds | Use both? |
|---|---|---|---|
| **Trivy Operator** | Scans workloads that are already running and writes reports as CRDs. | A gate *before* the pod starts (admission verifies the attestation), a mirror, and policy as CEL in git with expiring VEX exemptions. | suppline uses Trivy itself as its scanner; the Operator's reports of what runs overlap with the cluster agent's inventory. |
| **Harbor** (replication, proxy cache, scanning) | A registry that can mirror, scan, and block pulls above a severity. | A verdict that is signed and checked at admission rather than decided at pull time by the registry, policy that lives in your repo, and exemptions that expire. | Yes: Harbor is a good *target registry* for suppline. |
| **Kyverno / OPA alone** | Enforces policy at admission. | The thing to enforce: it produces the cosign attestation Kyverno verifies (`GET /api/v1/integration/kyverno/policy` returns the policy). | Yes: they are two halves of the same gate. |
| **regsync + a scanner + cosign + cron** | The same pipeline, assembled by hand. | One binary and one `suppline.yml` instead of the glue: a state machine for rescans and retries, tag cooldown, VEX expiry, attestation renewal, metrics. suppline's config *is* a regsync config with `x-` extensions, so existing mirroring rules carry over. | It replaces it. |

## Where suppline is not the right tool

- **You need to scan images you build and nothing else.** An in-place entry (`in-place:` in `suppline.yml`) scans and attests your own CI builds, but a build-time scanner in CI may be all you need.
- **You want a hosted service.** suppline is self-hosted with no phone-home; there is no SaaS.
- **You need SBOM or license management across a portfolio.** suppline writes an SBOM per digest but is not a portfolio tool.
- **You do not run Kubernetes.** The mirror and the scans work anywhere, but the admission half (Kyverno or OPA) assumes a cluster.

## Adopting it next to what you have

Nothing here needs a big-bang cutover:

1. Run the [eval](EVAL.md) to see one image pass and one fail.
2. Install the cluster agent on a cluster as it is. It reports what runs; suppline's `/api/v1/integration/kubernetes/clusters/{name}/migration` turns that into `sync:` entries.
3. Mirror a handful of images. The built-in default policy (no critical, no known-exploited high) is meant to be turned on the first week.
4. Apply the generated Kyverno policy in `Audit`, look at what it would deny, then switch to `Deny`.

[First cluster](FIRST_CLUSTER.md) walks through exactly that.
