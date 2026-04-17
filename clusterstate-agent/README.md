# clusterstate-agent

Kubernetes Deployment that continuously reports container image inventory observations from a cluster to the [suppline](https://github.com/daimoniac/suppline) supply-chain security gateway via its cluster-inventory webhook.

## What it does

While running, the agent:

1. Lists all pods across all namespaces using in-cluster RBAC (read-only `pods` permission).
2. Collects image references from Deployments, StatefulSets, DaemonSets, Jobs, and CronJobs.
3. Skips pods and workloads in excluded namespaces (configurable, defaults to `kube-system`, `kube-public`, `kube-node-lease`).
4. Extracts image reference, tag, and runtime digest from pod status for regular, init, and ephemeral containers (digests only available for running pods).
5. Deduplicates entries by `(namespace, image_ref, digest)`.
6. POSTs periodic snapshots to `POST /api/v1/webhook/cluster-inventory` on the suppline API.

This ensures suppline discovers images from scheduled jobs, pending deployments, and other workload definitions—even if no pods are currently running from those resources—while also capturing short-lived runtime workloads via pod and Event informers.

## Prerequisites

- Kubernetes 1.21+
- A running [suppline](https://github.com/daimoniac/suppline) instance reachable from within the cluster.
- Helm 3 (for chart deployment).

## Quick start (Helm)

```bash
helm install clusterstate-agent ./chart \
  --namespace suppline \
  --set clusterName=prod-eu-1 \
  --set suppline.url=http://suppline.suppline.svc.cluster.local:8080
```

With an API key:

```bash
helm install clusterstate-agent ./chart \
  --namespace suppline \
  --set clusterName=prod-eu-1 \
  --set suppline.url=http://suppline.suppline.svc.cluster.local:8080 \
  --set suppline.apiKey=my-secret-key
```

## Environment variables

The agent loads configuration from a `.env` file (if present) before checking environment variables. This allows easy local development without exporting shell variables.

| Variable | Required | Default | Description |
|---|---|---|---|
| `SUPPLINE_URL` | **yes** | — | Base URL of the suppline API, e.g. `http://suppline:8080` |
| `CLUSTER_NAME` | **yes** | — | Cluster identifier reported in the inventory payload |
| `SUPPLINE_API_KEY` | no | — | If set, sent as `Authorization: Bearer <key>` |
| `WATCH_FLUSH_INTERVAL` | no | `30s` | Interval for retrying failed inventory uploads (legacy name; maps to retry interval) |
| `WATCH_RETRY_INTERVAL` | no | `30s` | Interval for retrying failed inventory uploads |
| `WATCH_HEARTBEAT_INTERVAL` | no | `60m` | Maximum interval between inventory uploads, even when no observations changed |
| `WATCH_REFRESH_INTERVAL` | no | `24h` | Interval for full inventory refresh from pods/workloads |
| `EXCLUDED_NAMESPACES` | no | `kube-system,kube-public,kube-node-lease` | Comma-separated namespaces to skip |
| `LOG_LEVEL` | no | `info` | `debug` / `info` / `warn` / `error` |
| `DEBUG_DUMP_PAYLOAD` | no | `false` | If true, logs the full JSON payload before POST |
| `KUBECONFIG` | no | in-cluster | Override kubeconfig path (local development only) |

## Helm values

| Key | Default | Description |
|---|---|---|
| `watchFlushInterval` | `"30s"` | Interval for retrying failed inventory uploads (maps to `WATCH_FLUSH_INTERVAL`) |
| `watchHeartbeatInterval` | `"60m"` | Maximum interval between inventory uploads, even when no observations changed |
| `replicaCount` | `1` | Deployment replica count |
| `clusterName` | `""` | **Required** |
| `suppline.url` | `""` | **Required** |
| `suppline.apiKey` | `""` | Optional API key; creates a Secret when set |
| `excludedNamespaces` | `"kube-system,kube-public,kube-node-lease"` | Namespaces to skip |
| `logLevel` | `"info"` | Container log level |
| `image.repository` | `ghcr.io/daimoniac/clusterstate-agent` | Image repository |
| `image.tag` | `"latest"` | Image tag |
| `image.pullPolicy` | `Always` | Container image pull policy |
| `rbac.create` | `true` | Create ClusterRole + ClusterRoleBinding |
| `serviceAccount.create` | `true` | Create ServiceAccount |
| `resources` | see values.yaml | CPU/memory requests and limits |

The Deployment pod template includes the Helm release revision as an annotation, so each `helm upgrade` triggers a rolling restart of the clusterstate-agent pod.

## RBAC

The chart creates a **ClusterRole** with read-only permissions for pods and workload resources:

```yaml
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["events"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets", "daemonsets"]
  verbs: ["list"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["list"]
```

## Runtime observation

The chart deploys a `Deployment`, and the agent streams pod and Event observations into periodic batched webhook uploads.

```bash
helm upgrade --install clusterstate-agent ./chart \
  --namespace suppline \
  --set clusterName=prod-eu-1 \
  --set suppline.url=http://suppline.suppline.svc.cluster.local:8080 \
  --set watchFlushInterval=15s
```

## Building the image

```bash
docker build -t clusterstate-agent:dev .
```

From repo root, you can use Docker Compose release/deploy helpers:

```bash
# Build + push image
CLUSTERSTATE_AGENT_IMAGE=daimoniac/suppline-clusterstate-agent:latest \
  docker compose --profile release build --push clusterstate-agent-image

# Helm upgrade/install using the compose deploy helper
# (values can come from repo-root .env)
docker compose --profile deploy run --rm clusterstate-agent-helm
```

The compose deploy service executes `scripts/deploy-clusterstate-agent.sh` inside the Helm container.

If `CLUSTER_NAME` is unset, the deploy helper derives it from the active kube context:

```bash
kubectl config view --minify -o jsonpath='{.clusters[0].name}'
```

Example `.env` entries for deploy helper:

```dotenv
CLUSTER_NAME=prod-eu-1
SUPPLINE_URL=http://suppline.suppline.svc.cluster.local:8080
SUPPLINE_API_KEY=<key>
CLUSTERSTATE_AGENT_IMAGE_TAG=latest
```

No CGO. The binary is statically linked and runs in a minimal `alpine:3.21` image.

## Local development against a real cluster API

Use this when you want real pod inventory data from an existing cluster, but run the agent binary locally.

Create a `.env` file in the `clusterstate-agent` directory:

```bash
cp env.example .env
```

run the agent:

```bash
CLUSTER_NAME=$(kubectl config view --minify -o jsonpath='{.clusters[0].name}') go run .
```

## Restart in-cluster

If you need an immediate full resync cycle, restart the Deployment:

```bash
kubectl -n suppline rollout restart deployment/clusterstate-agent-clusterstate-agent
kubectl -n suppline rollout status deployment/clusterstate-agent-clusterstate-agent
kubectl -n suppline logs -f deployment/clusterstate-agent-clusterstate-agent
```
