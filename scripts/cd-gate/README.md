# CD gate (Kyverno image policy)

This directory holds the **Kyverno `verifyImages` / SCAI attestation** check used as a release gate: a synthetic `Pod` referencing your image is evaluated against `policy.yaml` using `kyverno apply --registry` (registry auth + remote attestation data).

## Contents

| File | Purpose |
|------|---------|
| `kyverno-gate.sh` | POSIX shell that runs the actual gate. Invoked by both CI and Compose so the logic lives in one place. |
| `policy.yaml` | `ClusterPolicy` with `verifyImages` rules (must be **committed** so CI clones include it). |
| `docker-compose.yml` | Local run: Alpine + bind-mount of this directory; runs `kyverno-gate.sh`. |
| `.gitlab-ci.yml` | GitLab job `kyverno-image-policy` (included from the repo root — see below); runs `kyverno-gate.sh`. |
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

Compose bind-mounts this directory (so the script and policy are available as `/work/gate/...`) and your image list (host path from `KYVERNO_IMAGES_FILE`, default `./images.txt`). `kyverno-gate.sh` installs the Kyverno CLI on first run and auto-detects `x86_64` / `arm64`.

You can also invoke the script directly (outside compose) if the Kyverno CLI is already on `PATH`:

```bash
REGISTRY_PASSWORD='...' \
KYVERNO_IMAGES_FILE=./images.txt \
./kyverno-gate.sh
```

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
| `KYVERNO_VERSION` | `1.17.1` | Kyverno CLI release. |
| `KYVERNO_POLICY_PATH` | `${CI_PROJECT_DIR}/scripts/cd-gate/policy.yaml` | Override path to the policy file. Relative paths resolve under `CI_PROJECT_DIR` (same as `KYVERNO_IMAGES_FILE`). |
| `KYVERNO_GATE_IMAGE` | `${CI_REGISTRY_IMAGE}/kyverno-gate:${KYVERNO_VERSION}` | Job image. Built by `build-kyverno-gate-image` (below). For `gitlab-ci-local`, override to `alpine:3.20`. |
| `KYVERNO_INSTALL_DIR` | `${CI_PROJECT_DIR}/.cache/kyverno-${KYVERNO_VERSION}` | Where the script installs the CLI when missing from `PATH`. Cached across pipelines. |
| `KYVERNO_JUNIT_OUTPUT` | `${CI_PROJECT_DIR}/kyverno-gate-junit.xml` | JUnit report path. Surfaced in the GitLab MR widget via `artifacts:reports:junit`. |

### Prebuilt job image

The gate job defaults to `${CI_REGISTRY_IMAGE}/kyverno-gate:${KYVERNO_VERSION}`. The `build-kyverno-gate-image` job (stage `cd-gate-build`) builds and pushes it with kaniko. Triggers:

- **Automatic:** commits to the default branch that change `scripts/cd-gate/Dockerfile`.
- **Manual:** available on every pipeline (`allow_failure: true`).

Bootstrap once (first pipeline, or when bumping `KYVERNO_VERSION`) by running the manual job; afterwards, the gate pulls the prebuilt image and the CLI install is skipped entirely.

Alternatively, build and push from a workstation:

```bash
docker build -f scripts/cd-gate/Dockerfile scripts/cd-gate \
  --build-arg KYVERNO_VERSION=1.17.1 \
  -t "${CI_REGISTRY_IMAGE}/kyverno-gate:1.17.1"
docker push "${CI_REGISTRY_IMAGE}/kyverno-gate:1.17.1"
```

### CLI cache

When the prebuilt image is not in use (e.g. `KYVERNO_GATE_IMAGE=alpine:3.20` under `gitlab-ci-local`), the script installs the CLI into `${CI_PROJECT_DIR}/.cache/kyverno-${KYVERNO_VERSION}/` and the job caches that directory (`cache.key = kyverno-cli-${KYVERNO_VERSION}`). Subsequent runs skip the `apk add` + tarball download — the cached binary is detected and reused. For `gitlab-ci-local`, pass `--mount-cache` to exercise the same path locally.

### JUnit report

The script writes `kyverno-gate-junit.xml` with one `<testcase>` per image (pass / fail / error). GitLab surfaces it in the MR test report widget via `artifacts.reports.junit`. Because failures are accumulated (not fail-fast), all images appear in the report even when some fail.

## gitlab-ci-local

- Tracked files only: untracked `policy.yaml`, `images.txt`, or `kyverno-gate.sh` will not appear in the simulated workspace. **Commit** them (or at least `git add`) before running.
- The first positional argument is a **job name**, not a stage. The job is **`kyverno-image-policy`**.
- Pass `--mount-cache` to exercise the same CLI cache the real CI uses.

The CI file auto-detects whether `CI_PROJECT_DIR` is the repo root or the `scripts/cd-gate/` directory itself, so either of the following works.

### From the repository root

```bash
gitlab-ci-local --file scripts/cd-gate/.gitlab-ci.yml kyverno-image-policy \
  --variable KYVERNO_IMAGES_FILE=scripts/cd-gate/images.txt \
  --variable REGISTRY_PASSWORD=secret
```

### From `scripts/cd-gate/` (treats this directory as the project)

```bash
cd scripts/cd-gate
gitlab-ci-local kyverno-image-policy \
  --variable KYVERNO_IMAGES_FILE=images.txt \
  --variable REGISTRY_PASSWORD=secret
```

## Troubleshooting

- **`Applying 0 policy rule(s)...`:** Kyverno did not load any rules (empty policy, parse error, or wrong path). Ensure the policy file exists in the clone and `KYVERNO_POLICY_PATH` points at the intended file.
- **`Applying N policy rule(s)...` with `pass: 0, fail: 0` (N > 0):** Rules loaded but **none applied** to the synthetic `Pod` the gate evaluates (wrong file, `match`/`kinds` not including `Pod`, or `exclude` matching the test namespace `local-test`). Omit `KYVERNO_POLICY_PATH` or set it to `scripts/cd-gate/policy.yaml`. The script fails on that summary so CI cannot pass silently; `--detailed-results` is always on so rule-level lines appear above the reason block.
- **Editing `kyverno-gate.sh`:** the script is POSIX shell (works under Alpine `ash` and `bash`). Keep it POSIX-compatible; `shellcheck` it before committing.
