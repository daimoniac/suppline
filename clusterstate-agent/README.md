# clusterstate-agent

Kubernetes CronJob that reports the running container image inventory of a cluster to the [suppline](https://github.com/daimoniac/suppline) supply-chain security gateway via its cluster-inventory webhook.

## What it does

On each run the agent:

1. Lists all pods across all namespaces using in-cluster RBAC (read-only `pods` permission).
2. Skips pods in excluded namespaces (configurable, defaults to `kube-system`, `kube-public`, `kube-node-lease`).
3. Extracts each container's image reference, tag, and runtime digest from pod status.
4. Deduplicates entries by `(namespace, image_ref, digest)`.
5. POSTs the snapshot to `POST /api/v1/webhook/cluster-inventory` on the suppline API.

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

The chart creates a **ClusterRole** with minimal read permissions:

```yaml
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
```

## Building the image

```bash
docker build -t clusterstate-agent:dev .
```

No CGO. The binary is statically linked and runs in a minimal `alpine:3.21` image.

## Local development

```bash
export SUPPLINE_URL=http://localhost:8080
export CLUSTER_NAME=local-dev
export KUBECONFIG=~/.kube/config   # uses your local kubeconfig
export DEBUG_DUMP_PAYLOAD=true

cd clusterstate-agent
go run .
```

## Debug option 2: local run against a real cluster API

Use this when you want real pod inventory data from an existing cluster, but run the agent binary locally.

1. Select your kubeconfig context:

```bash
export KUBECONFIG=$HOME/.kube/config
kubectl config use-context <your-context>
```

2. Make suppline reachable from your machine (example via port-forward):

```bash
kubectl -n suppline port-forward svc/suppline 8080:8080
```

3. Run the agent locally:

```bash
cd clusterstate-agent
export SUPPLINE_URL=http://127.0.0.1:8080
export CLUSTER_NAME=prod-eu-1
export EXCLUDED_NAMESPACES=kube-system,kube-public,kube-node-lease
export LOG_LEVEL=debug
export DEBUG_DUMP_PAYLOAD=true
# Optional if your webhook is protected:
export SUPPLINE_API_KEY=<api-key>
go run .
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
