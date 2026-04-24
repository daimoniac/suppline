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

```bash
export IMAGE_UNDER_TEST='your.registry.example/org/app:tag-or-digest'
export REGISTRY_PASSWORD='...'   # or PAT for the registry
# optional overrides:
# export REGISTRY_SERVER=docker.io
# export REGISTRY_USERNAME=...
# export KYVERNO_VERSION=1.17.1

docker compose run --rm kyverno-apply-test
```

Compose bind-mounts `./policy.yaml` into the container. The script installs the Kyverno CLI for `linux_x86_64` (use an amd64 machine or adjust the tarball URL).

## GitLab CI

The root of the repository should include the gate via `include`:

```yaml
include:
  - local: scripts/cd-gate/.gitlab-ci.yml
```

### Job

- **Name:** `kyverno-image-policy`
- **Stage:** `cd-gate`
- **Runs when:** `IMAGE_UNDER_TEST` is set (typically from an upstream build job or CI variable).

### Required CI/CD variables

| Variable | Description |
|----------|-------------|
| `IMAGE_UNDER_TEST` | Full image reference (`registry/repo@sha256:…` or `:tag`). |
| `REGISTRY_PASSWORD` | Registry token or PAT (**mask** in GitLab). |

### Optional variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REGISTRY_SERVER` | `docker.io` | Registry hostname for auth metadata. |
| `REGISTRY_USERNAME` | `hostingmaloonde` | Username for `~/.docker/config.json`. |
| `REGISTRY_AUTH_HOST` | (derived) | Override JSON key under `auths` if needed for your registry. |
| `KYVERNO_VERSION` | `1.17.1` | Kyverno CLI release to install when using the default Alpine image. |
| `KYVERNO_POLICY_PATH` | `${CI_PROJECT_DIR}/scripts/cd-gate/policy.yaml` | Override path to the policy file. |
| `KYVERNO_GATE_IMAGE` | `alpine:3.20` | Job image; set to your prebuilt image (below) to skip CLI download. |

### Faster pipelines: prebuilt job image

Build and push once 

```bash
docker build -f scripts/cd-gate/Dockerfile \
  --build-arg KYVERNO_VERSION=1.17.1 \
  -t "${CI_REGISTRY_IMAGE}/kyverno-gate:1.17.1" \
  scripts/cd-gate
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
gitlab-ci-local --file scripts/cd-gate/.gitlab-ci.yml kyverno-image-policy \
  --variable IMAGE_UNDER_TEST=repo/image:tag \
  --variable REGISTRY_PASSWORD=secret
```

## Troubleshooting

- **`Applying 0 policy rule(s)...` and `pass: 0, fail: 0`:** Kyverno did not load any policy file (wrong or missing path, or file not in the repo). Ensure `scripts/cd-gate/policy.yaml` exists in the clone and `KYVERNO_POLICY_PATH` is correct. The GitLab job and Compose script **fail the step** if the summary line contains both `pass: 0` and `fail: 0`, so this cannot silently pass CI. On failure they print a short **reason block** (policy path, image ref); `kyverno apply` is run with **`--detailed-results`** so the lines above that block carry rule-level detail from Kyverno.
- **YAML / `gitlab-ci-local`:** Lines like `echo "RESULT: PASS"` must be quoted in YAML so the colon is not parsed as a mapping.
