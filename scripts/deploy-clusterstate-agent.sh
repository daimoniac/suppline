#!/bin/sh
# Install/upgrade the clusterstate-agent chart from the Compose "deploy" profile.
# Invoked as the entrypoint of the clusterstate-agent-helm service; see
# docker-compose.yml for the environment it passes in.
set -eu

CHART_DIR="${CHART_DIR:-/workspace/clusterstate-agent/chart}"
HELM_RELEASE_NAME="${HELM_RELEASE_NAME:-clusterstate-agent}"
HELM_NAMESPACE="${HELM_NAMESPACE:-suppline}"
WATCH_FLUSH_INTERVAL="${WATCH_FLUSH_INTERVAL:-15s}"
CLUSTERSTATE_AGENT_IMAGE_REPOSITORY="${CLUSTERSTATE_AGENT_IMAGE_REPOSITORY:-daimon666/suppline-clusterstate-agent}"
CLUSTERSTATE_AGENT_IMAGE_TAG="${CLUSTERSTATE_AGENT_IMAGE_TAG:-latest}"
CLUSTER_NAME="${CLUSTER_NAME:-}"
SUPPLINE_URL="${SUPPLINE_URL:-}"
SUPPLINE_API_KEY="${SUPPLINE_API_KEY:-}"

die() {
    echo "$1" >&2
    exit 1
}

[ -n "$CLUSTER_NAME" ] || die "CLUSTER_NAME is required (reported as the cluster field in the inventory payload)."
[ -n "$SUPPLINE_URL" ] || die "SUPPLINE_URL is required (base URL of the suppline API reachable from within the cluster)."
[ -d "$CHART_DIR" ] || die "Chart not found at $CHART_DIR. Run from the repo root so ./ is mounted at /workspace."

set -- upgrade --install "$HELM_RELEASE_NAME" "$CHART_DIR" \
    --namespace "$HELM_NAMESPACE" \
    --create-namespace \
    --set-string "clusterName=$CLUSTER_NAME" \
    --set-string "suppline.url=$SUPPLINE_URL" \
    --set-string "watchFlushInterval=$WATCH_FLUSH_INTERVAL" \
    --set-string "image.repository=$CLUSTERSTATE_AGENT_IMAGE_REPOSITORY" \
    --set-string "image.tag=$CLUSTERSTATE_AGENT_IMAGE_TAG"

# Omitted when empty so the chart skips creating an empty API key Secret.
if [ -n "$SUPPLINE_API_KEY" ]; then
    set -- "$@" --set-string "suppline.apiKey=$SUPPLINE_API_KEY"
fi

echo "helm upgrade --install $HELM_RELEASE_NAME -n $HELM_NAMESPACE (cluster=$CLUSTER_NAME, suppline=$SUPPLINE_URL)"
exec helm "$@"
