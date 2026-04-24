# CD gate (Kyverno image policy)

This directory holds the **Kyverno `verifyImages` / SCAI attestation** check used as a release gate: a synthetic `Pod` referencing your image is evaluated against `policy.yaml` using `kyverno apply --registry` (registry auth + remote attestation data).

## Contents

| File | Purpose |
|------|---------|
| `policy.yaml` | `ClusterPolicy` with `verifyImages` rules (must be **committed** so CI clones include it). |
| `docker-compose.yml` | Local run: Alpine + Kyverno CLI + `docker login` + apply. |
| `.gitlab-ci.yml` | GitLab job `kyverno-image-policy` (included from the repo root — see below). |
| `Dockerfile` | Optional image with Kyverno CLI preinstalled to avoid downloading the CLI every pipeline. |

## Local run (Docker Compose)

From this directory:

Create a text file with **one full image reference per line** (empty lines and `#` comments are ignored), for example `images.txt`:

```text
your.registry.example/org/app:1.2.3
your.registry.example/other@sha256:abcd...
```

Then:

```bash
# Optional: host path to the list file (default ./images.txt next to this compose file)
# export KYVERNO_IMAGES_FILE="$PWD/images.txt"
export REGISTRY_PASSWORD='...'   # or PAT for the registry
# optional overrides:
# export REGISTRY_SERVER=docker.io
# export REGISTRY_USERNAME=...
# export KYVERNO_VERSION=1.17.1

docker compose run --rm kyverno-apply-test
```

Compose bind-mounts `./policy.yaml` and your image list (host path from `KYVERNO_IMAGES_FILE`, default `./images.txt` next to this file) into the container. The script installs the Kyverno CLI for `linux_x86_64` (use an amd64 machine or adjust the tarball URL).

## GitLab CI

The root of the repository should include the gate via `include`:

```yaml
include:
  - local: scripts/cd-gate/.gitlab-ci.yml
```

### Job

- **Name:** `kyverno-image-policy`
- **Stage:** `cd-gate`
- **Runs when:** `KYVERNO_IMAGES_FILE` is set to the path of the image list file (usually produced by an upstream job as an **artifact**).

### Required CI/CD variables

| Variable | Description |
|----------|-------------|
| `KYVERNO_IMAGES_FILE` | Path to a text file in the job workspace: one image ref per line (`registry/repo@sha256:…` or `:tag`). Relative paths resolve under `CI_PROJECT_DIR`. Lines whose first non-blank character is `#`, and blank lines, are skipped. |
| `REGISTRY_PASSWORD` | Registry token or PAT (**mask** in GitLab). |

### Optional variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REGISTRY_SERVER` | `docker.io` | Registry hostname for auth metadata. |
| `REGISTRY_USERNAME` | `hostingmaloonde` | Username for `~/.docker/config.json`. |
| `REGISTRY_AUTH_HOST` | (derived) | Override JSON key under `auths` if needed for your registry. |
| `KYVERNO_VERSION` | `1.17.1` | Kyverno CLI release to install when using the default Alpine image. |
| `KYVERNO_POLICY_PATH` | `${CI_PROJECT_DIR}/scripts/cd-gate/policy.yaml` | Override path to the policy file. Relative paths resolve under `CI_PROJECT_DIR` (same as `KYVERNO_IMAGES_FILE`). |
| `KYVERNO_GATE_IMAGE` | `alpine:3.20` | Job image; set to your prebuilt image (below) to skip CLI download. |

### Faster pipelines: prebuilt job image

Build and push once 

```bash
docker build -f  \
  --build-arg KYVERNO_VERSION=1.17.1 \
  -t "${CI_REGISTRY_IMAGE}/kyverno-gate:1.17.1" 
docker push "${CI_REGISTRY_IMAGE}/kyverno-gate:1.17.1"
```

Set in GitLab (or in `variables:`):

`KYVERNO_GATE_IMAGE` = `${CI_REGISTRY_IMAGE}/kyverno-gate:1.17.1`

The job skips installing Kyverno when the `kyverno` binary is already on `PATH`.

## gitlab-ci-local

- Tracked files only: untracked `policy.yaml` will not appear in the simulated workspace; **commit** it.
- The first positional argument is a **job name**, not a stage. The job is **`kyverno-image-policy`**.

From the repository root:

```bash
gitlab-ci-local kyverno-image-policy \
  --variable KYVERNO_IMAGES_FILE=scripts/cd-gate/images.txt \
  --variable REGISTRY_PASSWORD=secret
```

Ensure `images.txt` exists in the simulated workspace (tracked or created before the run), with one image reference per line.

## Troubleshooting

- **`Applying 0 policy rule(s)...`:** Kyverno did not load any rules (empty policy, parse error, or wrong path). Ensure the policy file exists in the clone and `KYVERNO_POLICY_PATH` points at the intended file.
- **`Applying N policy rule(s)...` with `pass: 0, fail: 0` (N > 0):** Rules loaded but **none applied** to the synthetic `Pod` Kyverno evaluates (wrong file, `match`/`kinds` not including `Pod`, or `exclude` matching the test namespace `local-test`). Omit `KYVERNO_POLICY_PATH` or set it to `scripts/cd-gate/policy.yaml`. The job **fails** on that summary so CI cannot pass silently; run with **`--detailed-results`** (already in the job) for rule-level lines above the reason block.
- **YAML / `gitlab-ci-local`:** Lines like `echo "RESULT: PASS"` must be quoted in YAML so the colon is not parsed as a mapping.
