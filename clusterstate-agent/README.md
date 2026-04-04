# clusterstate-agent

Kubernetes CronJob that reports the running container image inventory of a cluster to the [suppline](https://github.com/daimoniac/suppline) supply-chain security gateway via its cluster-inventory webhook.

## What it does

On each run the agent:

1. Lists all pods across all namespaces using in-cluster RBAC (read-only `pods` permission).
2. Collects image references from Deployments, StatefulSets, DaemonSets, Jobs, and CronJobs.
3. Skips pods and workloads in excluded namespaces (configurable, defaults to `kube-system`, `kube-public`, `kube-node-lease`).
4. Extracts each container's image reference, tag, and runtime digest from pod status (digests only available for running pods).
5. Deduplicates entries by `(namespace, image_ref, digest)`.
6. POSTs the snapshot to `POST /api/v1/webhook/cluster-inventory` on the suppline API.

This ensures suppline discovers images from scheduled jobs, pending deployments, and other workload definitions—even if no pods are currently running from those resources.

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
| `EXCLUDED_NAMESPACES` | no | `kube-system,kube-public,kube-node-lease` | Comma-separated namespaces to skip |
| `LOG_LEVEL` | no | `info` | `debug` / `info` / `warn` / `error` |
| `DEBUG_DUMP_PAYLOAD` | no | `false` | If true, logs the full JSON payload before POST |
| `KUBECONFIG` | no | in-cluster | Override kubeconfig path (local development only) |

## Helm values

| Key | Default | Description |
|---|---|---|
| `schedule` | `"0 * * * *"` | CronJob schedule (hourly) |
| `clusterName` | `""` | **Required** |
| `suppline.url` | `""` | **Required** |
| `suppline.apiKey` | `""` | Optional API key; creates a Secret when set |
| `excludedNamespaces` | `"kube-system,kube-public,kube-node-lease"` | Namespaces to skip |
| `logLevel` | `"info"` | Container log level |
| `image.repository` | `ghcr.io/daimoniac/clusterstate-agent` | Image repository |
| `image.tag` | `"latest"` | Image tag |
| `rbac.create` | `true` | Create ClusterRole + ClusterRoleBinding |
| `serviceAccount.create` | `true` | Create ServiceAccount |
| `failedJobsHistoryLimit` | `3` | Failed job history to retain |
| `successfulJobsHistoryLimit` | `1` | Successful job history to retain |
| `resources` | see values.yaml | CPU/memory requests and limits |

## RBAC

The chart creates a **ClusterRole** with read-only permissions for pods and workload resources:

```yaml
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets", "daemonsets"]
  verbs: ["list"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["list"]
```

## Building the image

```bash
docker build -t clusterstate-agent:dev .
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

## Run one-off in-cluster (without waiting for schedule)

1. Install the chart (or ensure the CronJob exists):

```bash
helm install clusterstate-agent ./chart \
  --namespace suppline \
  --set clusterName=prod-eu-1 \
  --set suppline.url=http://suppline.suppline.svc.cluster.local:8080
```

2. Start an immediate Job from the CronJob template:

```bash
kubectl -n suppline create job \
  --from=cronjob/clusterstate-agent-clusterstate-agent \
  csa-debug-now
```

3. Watch logs:

```bash
kubectl -n suppline logs -f job/csa-debug-now
```
