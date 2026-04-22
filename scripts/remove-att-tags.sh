#!/usr/bin/env bash
# remove-att-tags.sh — Delete all *.att tags from every repository in a Docker Hub namespace.
#
# Usage:
#   DOCKERHUB_USERNAME=<user> DOCKERHUB_PASSWORD=<pass> ./scripts/remove-att-tags.sh [NAMESPACE]
#
# The NAMESPACE argument defaults to "hostingmaloonde".
# Set DRY_RUN=1 to print what would be deleted without actually deleting.

set -euo pipefail

NAMESPACE="${1:-hostingmaloonde}"
DOCKERHUB_API="https://hub.docker.com/v2"
DRY_RUN="${DRY_RUN:-0}"

# ── Prerequisites ─────────────────────────────────────────────────────────────

if ! command -v jq &>/dev/null; then
  echo "ERROR: jq is required but not installed." >&2
  exit 1
fi

# ── Credentials ──────────────────────────────────────────────────────────────

: "${DOCKERHUB_USERNAME:?Set DOCKERHUB_USERNAME}"
: "${DOCKERHUB_PASSWORD:?Set DOCKERHUB_PASSWORD}"

# ── Authenticate ─────────────────────────────────────────────────────────────

echo "Authenticating as ${DOCKERHUB_USERNAME} ..."
login_response=$(curl -fsSL -X POST "${DOCKERHUB_API}/users/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${DOCKERHUB_USERNAME}\",\"password\":\"${DOCKERHUB_PASSWORD}\"}")

TOKEN=$(echo "${login_response}" | jq -r '.token // empty')

if [[ -z "${TOKEN}" ]]; then
  echo "ERROR: Authentication failed." >&2
  echo "${login_response}" | jq . >&2 || echo "${login_response}" >&2
  exit 1
fi

AUTH_HEADER="Authorization: JWT ${TOKEN}"

# ── Helpers ───────────────────────────────────────────────────────────────────

# Paginate through a Docker Hub list endpoint and print .name of each result.
list_names() {
  local url="$1"
  while [[ -n "${url}" ]]; do
    local page
    page=$(curl -fsSL -H "${AUTH_HEADER}" "${url}")
    echo "${page}" | jq -r '.results[].name'
    url=$(echo "${page}" | jq -r '.next // empty')
  done
}

# ── Main ──────────────────────────────────────────────────────────────────────

deleted=0
skipped=0

echo "Listing repositories under namespace '${NAMESPACE}' ..."
mapfile -t repos < <(list_names "${DOCKERHUB_API}/repositories/${NAMESPACE}/?page_size=100")

if [[ ${#repos[@]} -eq 0 ]]; then
  echo "No repositories found (or namespace does not exist)."
  exit 0
fi

echo "Found ${#repos[@]} repositor(ies)."

for repo in "${repos[@]}"; do
  echo ""
  echo "── ${NAMESPACE}/${repo} ──────────────────────"
  mapfile -t tags < <(list_names "${DOCKERHUB_API}/repositories/${NAMESPACE}/${repo}/tags?page_size=100")

  for tag in "${tags[@]}"; do
    # Match tags ending in .att (e.g. sha256-abc123.att)
    if [[ "${tag}" == *.sig ]]; then
      if [[ "${DRY_RUN}" == "1" ]]; then
        echo "  [DRY RUN] would delete: ${NAMESPACE}/${repo}:${tag}"
        ((deleted++)) || true
      else
        echo "  Deleting: ${NAMESPACE}/${repo}:${tag}"
        http_code=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
          -H "${AUTH_HEADER}" \
          "${DOCKERHUB_API}/repositories/${NAMESPACE}/${repo}/tags/${tag}/")
        if [[ "${http_code}" == "204" ]]; then
          echo "  Deleted (HTTP 204)"
          ((deleted++)) || true
        else
          echo "  WARNING: Unexpected HTTP ${http_code} for ${repo}:${tag}" >&2
          ((skipped++)) || true
        fi
      fi
    fi
  done
done

echo ""
echo "Done. Deleted: ${deleted}  Skipped/errored: ${skipped}"
