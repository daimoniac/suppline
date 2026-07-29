#!/bin/sh
# Eval attestation gate POC — same checks Kyverno verifyImages uses for SCAI:
#   1) signature verifies with the demo public key
#   2) evidence.validUntil is still in the future
#   3) evidence.scanStatus is passed / passed-with-exceptions  → ADMIT
#      anything else (e.g. failed)                              → DENY
#
# Expects the zero-cred Compose eval stack to be up (docs/EVAL.md).
#
# Usage (host):
#   ./scripts/eval-attestation-gate.sh
#
# Or via Compose (no local cosign/jq required):
#   docker compose --profile eval-gate run --rm eval-gate

set -eu

API_URL=${SUPPLINE_API_URL:-http://localhost:8080}
API_KEY=${SUPPLINE_API_KEY:-demo}
REGISTRY=${EVAL_REGISTRY:-localhost:5000}
PUBKEY=${EVAL_COSIGN_PUBKEY:-keys/demo/cosign.pub}
SCAI_TYPE='https://in-toto.io/attestation/scai/attribute-report/v0.3'

PASS_REPO=${EVAL_PASS_REPO:-demo-pass}
FAIL_REPO=${EVAL_FAIL_REPO:-demo-fail}

log() { printf '==> %s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"
}

need cosign
need jq
need curl

[ -f "$PUBKEY" ] || die "public key not found: $PUBKEY (start the eval stack once so keys/demo is generated)"

log "waiting for API at $API_URL"
i=0
while [ "$i" -lt 60 ]; do
    if curl -sf -H "Authorization: Bearer $API_KEY" "$API_URL/api/v1/scans?limit=1" >/dev/null 2>&1; then
        break
    fi
    i=$((i + 1))
    sleep 2
done
[ "$i" -lt 60 ] || die "API not ready / unauthorized (expected key '$API_KEY')"

# Resolve digest + policy flag for a repository prefix (API uses registry:5000/… refs).
resolve_scan() {
    repo_suffix=$1
    curl -sf -H "Authorization: Bearer $API_KEY" "$API_URL/api/v1/scans" | jq -c --arg suf "$repo_suffix" '
      [ .[] | select((.Repository // "") | endswith($suf)) ] | .[0] // empty
    '
}

verify_scai() {
    image_ref=$1
    cosign verify-attestation \
        --type "$SCAI_TYPE" \
        --key "$PUBKEY" \
        --allow-http-registry \
        --insecure-ignore-tlog \
        "$image_ref" 2>/dev/null | jq -r '.payload' | base64 -d
}

gate_would_admit() {
    # stdin: decoded in-toto statement JSON
    # exit 0 = admit, 1 = deny (mirrors Kyverno conditions)
    # Strip fractional seconds — jq fromdateiso8601 only accepts whole seconds.
    jq -e '
      (.predicate.evidence.scanStatus // "") as $status |
      ((.predicate.evidence.validUntil // "") | sub("\\.[0-9]+Z$"; "Z") | sub("\\.[0-9]+\\+"; "+")) as $until |
      ($until != "") and (($until | fromdateiso8601) > now) and
      ($status == "passed" or $status == "passed-with-exceptions")
    ' >/dev/null
}

log "resolving demo scans from API"
PASS_JSON=$(resolve_scan "$PASS_REPO")
FAIL_JSON=$(resolve_scan "$FAIL_REPO")
[ -n "$PASS_JSON" ] || die "no scan found for *$PASS_REPO — wait for the eval pipeline to finish"
[ -n "$FAIL_JSON" ] || die "no scan found for *$FAIL_REPO — wait for the eval pipeline to finish"

PASS_DIGEST=$(printf '%s' "$PASS_JSON" | jq -r '.Digest')
FAIL_DIGEST=$(printf '%s' "$FAIL_JSON" | jq -r '.Digest')
PASS_PASSED=$(printf '%s' "$PASS_JSON" | jq -r '.PolicyPassed')
FAIL_PASSED=$(printf '%s' "$FAIL_JSON" | jq -r '.PolicyPassed')

PASS_REF="${REGISTRY}/${PASS_REPO}@${PASS_DIGEST}"
FAIL_REF="${REGISTRY}/${FAIL_REPO}@${FAIL_DIGEST}"

printf '    pass image: %s (PolicyPassed=%s)\n' "$PASS_REF" "$PASS_PASSED"
printf '    fail image: %s (PolicyPassed=%s)\n' "$FAIL_REF" "$FAIL_PASSED"

log "verifying SCAI on pass image (expect ADMIT)"
PASS_STMT=$(verify_scai "$PASS_REF") || die "cosign could not verify SCAI on pass image"
PASS_STATUS=$(printf '%s' "$PASS_STMT" | jq -r '.predicate.evidence.scanStatus')
printf '    scanStatus=%s\n' "$PASS_STATUS"
if printf '%s' "$PASS_STMT" | gate_would_admit; then
    log "ADMIT ok for $PASS_REPO"
else
    die "gate would DENY $PASS_REPO (scanStatus=$PASS_STATUS) — expected ADMIT"
fi

log "verifying SCAI on fail image (expect DENY)"
FAIL_STMT=$(verify_scai "$FAIL_REF") || die "cosign could not verify SCAI on fail image (signature should still exist)"
FAIL_STATUS=$(printf '%s' "$FAIL_STMT" | jq -r '.predicate.evidence.scanStatus')
printf '    scanStatus=%s\n' "$FAIL_STATUS"
if printf '%s' "$FAIL_STMT" | gate_would_admit; then
    die "gate would ADMIT $FAIL_REPO (scanStatus=$FAIL_STATUS) — expected DENY"
else
    log "DENY ok for $FAIL_REPO (attestation present, scanStatus=$FAIL_STATUS)"
fi

printf '\n=== attestation gate POC passed ===\n'
printf 'demo-pass would be admitted; demo-fail would be rejected — same rules as the Kyverno ClusterPolicy.\n'
printf 'Fetch the cluster policy from the host with:\n'
printf '  curl -s -H "Authorization: Bearer %s" http://localhost:8080/api/v1/integration/kyverno/policy\n' "$API_KEY"
