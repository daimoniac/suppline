#!/bin/sh
# Kyverno verifyImages (SCAI) gate.
#
# For each image in an images-list file, build a synthetic Pod manifest and
# evaluate the Kyverno policy against it using `kyverno apply --registry`.
# Shared by GitLab CI (.gitlab-ci.yml) and the local compose harness
# (docker-compose.yml) so the logic lives in exactly one place.
#
# Usage:
#   kyverno-gate.sh [--policy FILE] [--images FILE]
#
# Environment (fallbacks used when flags are absent):
#   KYVERNO_POLICY_PATH   Policy file (default: <script dir>/policy.yaml)
#   KYVERNO_IMAGES_FILE   Images list, one ref per line, '#' comments allowed
#   KYVERNO_VERSION       CLI version to install if `kyverno` is not on PATH
#   KYVERNO_INSTALL_DIR   Where to install the CLI if missing (default /usr/local/bin).
#                         Set to a cache-friendly path (e.g. $CI_PROJECT_DIR/.cache/kyverno)
#                         to let GitLab cache the binary across pipelines.
#   KYVERNO_JUNIT_OUTPUT  If set, write a JUnit XML report with one <testcase> per
#                         image to this path. Implies 'run all images, fail at end'.
#   REGISTRY_SERVER       Registry host for docker auth (default docker.io)
#   REGISTRY_USERNAME     Registry username
#   REGISTRY_PASSWORD     Registry token / PAT (required)
#   REGISTRY_AUTH_HOST    Override the key used in ~/.docker/config.json
#   CI_PROJECT_DIR        Used to resolve relative paths (GitLab convention)

set -eu

KYVERNO_VERSION=${KYVERNO_VERSION:-1.17.1}
KYVERNO_INSTALL_DIR=${KYVERNO_INSTALL_DIR:-/usr/local/bin}
KYVERNO_JUNIT_OUTPUT=${KYVERNO_JUNIT_OUTPUT:-}
REGISTRY_SERVER=${REGISTRY_SERVER:-docker.io}
REGISTRY_USERNAME=${REGISTRY_USERNAME:-}
REGISTRY_PASSWORD=${REGISTRY_PASSWORD:-}
REGISTRY_AUTH_HOST=${REGISTRY_AUTH_HOST:-}

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
POLICY_FILE=${KYVERNO_POLICY_PATH:-}
IMAGES_FILE=${KYVERNO_IMAGES_FILE:-}

while [ $# -gt 0 ]; do
    case "$1" in
        --policy) POLICY_FILE=$2; shift 2 ;;
        --images) IMAGES_FILE=$2; shift 2 ;;
        -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  {
    printf '\n=== Kyverno gate failed: %s ===\n' "$1" >&2
    shift
    for msg in "$@"; do printf '%s\n' "$msg" >&2; done
    exit 1
}

resolve_path() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *)  printf '%s/%s\n' "${CI_PROJECT_DIR:-$PWD}" "$1" ;;
    esac
}

ensure_kyverno() {
    # Honor the install dir (may already hold a cached binary from a previous pipeline).
    case ":$PATH:" in
        *":$KYVERNO_INSTALL_DIR:"*) : ;;
        *) PATH="$KYVERNO_INSTALL_DIR:$PATH"; export PATH ;;
    esac

    if command -v kyverno >/dev/null 2>&1; then
        installed_version=$(kyverno version 2>/dev/null | awk '/^Version:/ { print $2; exit }')
        if [ "$installed_version" = "$KYVERNO_VERSION" ] || [ -z "$installed_version" ]; then
            log "kyverno already available ($(command -v kyverno))"
            return 0
        fi
        log "kyverno $installed_version found, reinstalling v${KYVERNO_VERSION}"
    fi

    command -v apk >/dev/null 2>&1 || die \
        "kyverno CLI not found and installer only supports Alpine" \
        "Preinstall the CLI in your image or use KYVERNO_GATE_IMAGE."

    case "$(uname -m)" in
        x86_64|amd64)  k_arch=x86_64 ;;
        aarch64|arm64) k_arch=arm64 ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac

    log "installing kyverno CLI v${KYVERNO_VERSION} (${k_arch}) -> ${KYVERNO_INSTALL_DIR}"
    apk add --no-cache --quiet ca-certificates curl tar >/dev/null
    url="https://github.com/kyverno/kyverno/releases/download/v${KYVERNO_VERSION}/kyverno-cli_v${KYVERNO_VERSION}_linux_${k_arch}.tar.gz"
    mkdir -p "$KYVERNO_INSTALL_DIR"
    curl -fsSL -o /tmp/kyverno.tgz "$url"
    tar -xzf /tmp/kyverno.tgz -C "$KYVERNO_INSTALL_DIR" kyverno
    chmod +x "$KYVERNO_INSTALL_DIR/kyverno"
    rm -f /tmp/kyverno.tgz
}

write_docker_auth() {
    [ -n "$REGISTRY_PASSWORD" ] || die \
        "REGISTRY_PASSWORD is not set" \
        "Set REGISTRY_PASSWORD (and REGISTRY_USERNAME) to a registry token or PAT."
    : "${REGISTRY_USERNAME:?REGISTRY_USERNAME required when REGISTRY_PASSWORD is set}"

    if [ -n "$REGISTRY_AUTH_HOST" ]; then
        key=$REGISTRY_AUTH_HOST
    elif [ "$REGISTRY_SERVER" = "docker.io" ]; then
        key=https://index.docker.io/v1/
    else
        key=$REGISTRY_SERVER
    fi

    auth=$(printf '%s:%s' "$REGISTRY_USERNAME" "$REGISTRY_PASSWORD" | base64 | tr -d '\n')
    mkdir -p "$HOME/.docker"
    umask 077
    printf '{"auths":{"%s":{"auth":"%s"}}}\n' "$key" "$auth" > "$HOME/.docker/config.json"
    log "wrote docker auth for $key"
}

write_pod_manifest() {
    _img=$1
    _out=$2
    cat > "$_out" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: image-policy-test
  namespace: local-test
spec:
  containers:
  - name: app
    image: $_img
  restartPolicy: Never
EOF
}

# Count non-empty, non-comment lines so we can render [i/N] progress.
count_images() {
    awk '
        { sub(/#.*/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, "") }
        NF { n++ }
        END { print n + 0 }
    ' "$1"
}

# XML helpers used by the JUnit emitter. sed expressions must quote '&' first.
xml_attr() {
    printf '%s' "$1" | sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g' \
        -e "s/'/\&apos;/g"
}
xml_cdata() {
    # Escape the CDATA terminator so we can safely wrap arbitrary output.
    printf '%s' "$1" | sed 's/]]>/]]]]><![CDATA[>/g'
}

append_junit_case() {
    _name=$1; _status=$2; _msg=$3; _out=$4
    {
        printf '  <testcase classname="kyverno-image-gate" name="%s" time="0">\n' "$(xml_attr "$_name")"
        case "$_status" in
            pass) : ;;
            fail)
                printf '    <failure message="%s" type="KyvernoGateFailure"><![CDATA[%s]]></failure>\n' \
                    "$(xml_attr "$_msg")" "$(xml_cdata "$_out")"
                ;;
            error)
                printf '    <error message="%s" type="KyvernoGateError"><![CDATA[%s]]></error>\n' \
                    "$(xml_attr "$_msg")" "$(xml_cdata "$_out")"
                ;;
        esac
        printf '    <system-out><![CDATA[%s]]></system-out>\n' "$(xml_cdata "$_out")"
        printf '  </testcase>\n'
    } >> "$junit_cases"
}

write_junit_report() {
    [ -n "$KYVERNO_JUNIT_OUTPUT" ] || return 0
    mkdir -p "$(dirname -- "$KYVERNO_JUNIT_OUTPUT")"
    {
        printf '<?xml version="1.0" encoding="UTF-8"?>\n'
        printf '<testsuites name="kyverno-image-gate" tests="%d" failures="%d" errors="0" time="0">\n' \
            "$tested" "$failures"
        printf '<testsuite name="kyverno-image-gate" tests="%d" failures="%d" errors="0" time="0">\n' \
            "$tested" "$failures"
        cat "$junit_cases"
        printf '</testsuite>\n'
        printf '</testsuites>\n'
    } > "$KYVERNO_JUNIT_OUTPUT"
    log "wrote JUnit report: $KYVERNO_JUNIT_OUTPUT"
}

run_gate() {
    total=$(count_images "$IMAGES_FILE")
    [ "$total" -gt 0 ] || die \
        "no image refs in images list (blank or comment-only file)" \
        "File: $IMAGES_FILE"

    tmpdir=$(mktemp -d)
    trap 'write_junit_report; rm -rf "$tmpdir"' EXIT
    manifest=$tmpdir/pod.yaml
    junit_cases=$tmpdir/junit-cases.xml
    : > "$junit_cases"

    line_no=0
    tested=0
    failures=0

    while IFS= read -r line || [ -n "$line" ]; do
        line_no=$((line_no + 1))
        img=$(printf '%s' "$line" | sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//')
        [ -z "$img" ] && continue
        tested=$((tested + 1))

        printf '\n---[ %d/%d ] %s (line %d)\n' "$tested" "$total" "$img" "$line_no"
        write_pod_manifest "$img" "$manifest"

        set +e
        out=$(kyverno apply "$POLICY_FILE" \
            --resource "$manifest" \
            --registry \
            --remove-color \
            --detailed-results 2>&1)
        ec=$?
        set -e
        printf '%s\n' "$out"

        if printf '%s\n' "$out" | grep -qE 'pass:[[:space:]]*0,[[:space:]]*fail:[[:space:]]*0'; then
            failures=$((failures + 1))
            msg="no rule results (pass:0, fail:0) — policy did not apply to synthetic Pod"
            printf 'FAIL: %s\n' "$msg" >&2
            append_junit_case "$img" fail "$msg" "$out"
            continue
        fi

        if [ "$ec" -ne 0 ]; then
            failures=$((failures + 1))
            msg="kyverno apply exited $ec"
            printf 'FAIL: %s\n' "$msg" >&2
            append_junit_case "$img" fail "$msg" "$out"
            continue
        fi

        append_junit_case "$img" pass "" "$out"
    done < "$IMAGES_FILE"

    if [ "$failures" -gt 0 ]; then
        die "$failures of $tested image(s) failed verification" \
            "Policy: $POLICY_FILE" \
            "Images: $IMAGES_FILE" \
            "See per-image output above for rule-level detail."
    fi

    printf '\n=== Kyverno gate: PASS (%d image(s) from %s) ===\n' \
        "$tested" "$IMAGES_FILE"
}

POLICY_FILE=${POLICY_FILE:-$SCRIPT_DIR/policy.yaml}
POLICY_FILE=$(resolve_path "$POLICY_FILE")
IMAGES_FILE=$(resolve_path "${IMAGES_FILE:?set KYVERNO_IMAGES_FILE or pass --images}")

[ -f "$POLICY_FILE" ] || die "policy file missing" \
    "Expected policy at: $POLICY_FILE" \
    "Fix: add scripts/cd-gate/policy.yaml, or set KYVERNO_POLICY_PATH."
[ -f "$IMAGES_FILE" ] || die "images list missing" \
    "Expected images list at: $IMAGES_FILE"
[ -s "$IMAGES_FILE" ] || die "images list is empty" "File: $IMAGES_FILE"

log "policy: $POLICY_FILE"
log "images: $IMAGES_FILE"

ensure_kyverno
write_docker_auth
kyverno version
run_gate
