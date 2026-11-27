---
layout: default
title: First cluster
description: Put suppline in front of the images a cluster already runs, without a big-bang cutover
---

# First cluster

This page takes you from nothing to suppline gating the third-party images of one cluster. It starts from what the cluster already runs, so you do not write a `sync:` list from scratch, and every step that can block a pod starts in a mode that only reports.

The order is the point. Each step is useful alone, and nothing is enforced until the last one:

1. Install suppline and the cluster agent. The agent only reports what runs.
2. Turn the report into `sync:` entries. suppline mirrors, scans and attests those images.
3. Look at what passes. The [built-in default policy](POLICY.md#default-policy) needs no configuration.
4. Ask what a stricter policy would block, before you adopt it.
5. Apply the admission policy in `Audit`, read the reports, then switch it to `Deny`.
6. Point pods at the mirror, one labeled namespace at a time.

You need a Kubernetes cluster you can install into, `helm`, `kubectl`, and [Kyverno](https://kyverno.io) with the `policies.kyverno.io/v1` API (tested with Kyverno 1.20). To try the whole sequence on a throwaway cluster first, use `kind`.

## 1. Install suppline and the agent

For a **lab** (a kind or minikube cluster you will delete), use the bundled registry and no volumes. The lab values file is in the repository, so run this from a checkout:

```bash
cosign generate-key-pair   # asks for a password; keep cosign.key, it signs the attestations

helm upgrade --install suppline charts/suppline -n suppline --create-namespace \
  -f charts/suppline/values-lab.yaml \
  --set backend.secrets.SUPPLINE_API_KEY=change-me \
  --set-file backend.secrets.ATTESTATION_KEY=<(base64 -w0 cosign.key) \
  --set backend.secrets.ATTESTATION_KEY_PASSWORD='<the password you chose>'
```

For a **real cluster**, bring your own registry (Harbor, ECR, ACR, Artifactory) instead: leave `registry.enabled` at `false` and set `SUPPLINE_REGISTRY_URL`, `SUPPLINE_REGISTRY_USERNAME` and `SUPPLINE_REGISTRY_PASSWORD` in `values-secrets.yaml` (see [REGISTRY.md](REGISTRY.md) and `charts/suppline/values-secrets.yaml.example`). Do not use the bundled registry for anything you keep. Kyverno and the nodes must reach it, trust its self-signed certificate and authenticate to it, and none of that is set up by default; [Lab only: use the bundled registry](#lab-only-use-the-bundled-registry) shows the steps.

Reach the API from your machine. Use the pod rather than the Service, because the bundled Postgres and registry pods match the Service's label selector too:

```bash
kubectl -n suppline port-forward \
  $(kubectl -n suppline get pods -l 'app.kubernetes.io/name=suppline,!app.kubernetes.io/component' -o name) 8080:8080
```

Install the agent in the same cluster. It lists pods and workloads read-only and sends the images to suppline:

```bash
helm upgrade --install clusterstate-agent clusterstate-agent/chart -n suppline \
  --set clusterName=my-cluster \
  --set suppline.url=http://suppline.suppline.svc.cluster.local:8080 \
  --set suppline.apiKey=change-me
```

Within a minute the cluster appears under **Integrations → Kubernetes Clusters** in the UI (`http://localhost:8080`, log in with your API key).

## 2. Turn what runs into `sync:` entries

```bash
curl -s -H "Authorization: Bearer change-me" \
  "http://localhost:8080/api/v1/integration/kubernetes/clusters/my-cluster/migration?exclude=registry.example.com"
```

The response is a commented YAML snippet. The same plan is a **Migration plan** button in the UI. It lists every running image that is neither already on the mirror nor already copied by a `sync:` entry, with the target name suppline will use (`<mirror>/<path with "/" turned into "_">`, so `grafana/grafana:11.2.0` becomes `…/grafana_grafana:11.2.0`).

Read it before you use it:

- `exclude=` drops registries whose images you build yourself. They belong in your own registry, not in the mirror.
- Images pinned only by digest are listed as warnings: a sync entry copies by tag, so add one with the tag the image was built from.
- Two repositories that flatten to the same name are warned about. Give all but one a hand-written `target`.
- Pass `?mirror=<registry/prefix>` to write a literal target. Without it the targets read `{{ env "SUPPLINE_REGISTRY_URL" }}`, which is what you want in the config file.

Paste the entries under `sync:` in your `suppline.yml` (the chart's `backend.supplineConfig`), then upgrade the release:

```bash
helm upgrade suppline charts/suppline -n suppline --reuse-values \
  --set-file backend.supplineConfig=suppline.yml
```

Start with a handful of images, not all of them. suppline copies each one, scans it, applies the policy and signs a verdict. A large image such as Grafana takes a minute or two on the first scan.

## 3. Look at what passes

You did not set a policy, so every image is judged by the built-in default: **no critical, and no known-exploited (CISA KEV) high, vulnerabilities**, ignoring kernel header packages. That is the policy to run in the first week. It blocks what is both severe and being exploited, so it rarely blocks something you cannot act on.

```bash
curl -s -H "Authorization: Bearer change-me" "http://localhost:8080/api/v1/repositories" |
  jq -r '.Repositories[] | [.Name, .PolicyStatus, .VulnerabilityCount.Critical] | @tsv'
```

In the UI the policy reads as sentences ("No critical or known-exploited high vulnerabilities…"), not as "custom policy". A real run of a lab cluster gave:

| Image | Critical | High | Result |
|---|---:|---:|---|
| `redis:7-alpine` | 0 | 2 | passed |
| `nginx:1.27-alpine` | 3 | 67 | failed |
| `grafana/grafana:11.2.0` | 9 | 137 | failed |
| `ghcr.io/jqlang/jq:1.7.1` | 0 | 0 | passed |

Failed images are not removed from the mirror. They keep their verdict, and the verdict is what admission reads. A VEX exemption (see [VEX in the policy guide](POLICY.md#interaction-with-vex-statements)) is the way to move a failed image to passed when a finding does not apply to how you run it.

## 4. Ask what a stricter policy would block

Before you tighten the policy, replay the scans you already have through the stricter expression. Nothing is saved or changed:

```bash
curl -s -X POST -H "Authorization: Bearer change-me" -H 'Content-Type: application/json' \
  -d '{"expression": "criticalCount == 0 && highCount == 0", "in_use_only": true}' \
  http://localhost:8080/api/v1/policies/preview | jq
```

`WouldFail` counts the images that fail the new expression, `NewlyBlocked` those that pass today and would fail, and `Images` lists the first of them with the CVEs behind it. Set `in_use_only` to `false` to cover everything suppline has scanned. See [Preview a stricter policy](POLICY.md#preview-a-stricter-policy).

## 5. Admission: report first, then enforce

Generate the Kyverno policy from your signing key and apply it. It starts with `validationActions: [Audit]`, so it records results and denies nothing:

```bash
curl -s http://localhost:8080/api/v1/integration/kyverno/policy | kubectl apply -f -
kubectl get policyreport,ephemeralreport -A
```

A pod passes when its image has a SCAI attestation signed by your key with `scanStatus` of `passed` or `passed-with-exceptions` and a `validUntil` in the future. Pods of images that were never mirrored report a failure or an error: that list is your remaining work. If every result is an **error** that names the registry (`failed to get imagedata`), Kyverno cannot reach the mirror or does not trust its certificate; fix that first, since a `Deny` policy would then block everything.

When the reports are clean, edit `validationActions` to `[Deny]` and apply the policy again. Enforce in the namespaces you have already migrated before the whole cluster: the generated policy skips `kube-system`, `kyverno` and `suppline`, and you can narrow it further with a `namespaceSelector`.

## 6. Pull from the mirror

An attestation proves an image is fine. It does not make the pod pull from your registry; for that, rewrite the image names. Generate the policy once the images are synced:

```bash
curl -s -H "Authorization: Bearer change-me" \
  "http://localhost:8080/api/v1/integration/kyverno/mirror-rewrite?registries=docker.io,ghcr.io" |
  kubectl apply -f -

kubectl label namespace my-app suppline.cloud/mirror=true
```

The generated `MutatingPolicy` only touches namespaces carrying `suppline.cloud/mirror=true` (use `&scope=all` for every namespace except the system ones). It rewrites images from the listed registries to the names the migration plan syncs them under and leaves other registries alone. It changes **pods only**, so the Deployments in your Git repository stay as written and a GitOps tool sees no drift, and it **fails open**: if Kyverno is down, a pod keeps its upstream image and the `Deny` policy from step 5 is what blocks it.

Check it on a new pod before you rely on it:

```bash
kubectl -n my-app get pod -o jsonpath='{range .items[*].spec.containers[*]}{.image}{"\n"}{end}'
```

Every image from a listed registry must exist on the mirror first, or its pod will not start. Run the migration plan again after a rollout to see what is left.

**Regenerate the admission policy with `pods_only=true` before you enforce.** Kyverno copies an `ImageValidatingPolicy` onto Deployments, StatefulSets and the other pod controllers. A Deployment still names the upstream image, because the rewrite only changes pods, so that copy looks for an attestation on `docker.io/...`, finds none and rejects the Deployment under `Deny`. With `pods_only=true` the policy checks pods only, after the rewrite, which is where the final image is known:

```bash
curl -s -H "Authorization: Bearer change-me" \
  "http://localhost:8080/api/v1/integration/kyverno/policy?pods_only=true" | kubectl apply -f -
```

Pods created by a Deployment are still checked, so a Deployment of a failed image is created and then cannot start its pods (`kubectl describe rs` shows the denial).

## Lab only: use the bundled registry

The bundled registry serves HTTPS with a self-signed certificate and a password. Four things must be true before steps 5 and 6 work against it. None of them is needed with a registry that has a certificate your cluster already trusts (Harbor, ECR, ACR). The commands below are what was tested on kind v0.33 (containerd 2.3) with Kyverno 1.20. Replace `kind-control-plane` with your node container.

Use the registry's full in-cluster name everywhere Kyverno or a node looks it up. The short name `suppline-registry` resolves only inside the `suppline` namespace, and the certificate lists these names:

```bash
REG=suppline-registry.suppline.svc.cluster.local:5000
NODE=kind-control-plane
kubectl -n suppline exec suppline-registry-0 -c registry -- cat /certs/tls.crt > registry-ca.crt
```

**1. Nodes: name, trust and a pull secret.** Nodes do not use cluster DNS. Map the name to the Service address, tell containerd to trust the certificate, and give the pods a pull secret:

```bash
CIP=$(kubectl -n suppline get svc suppline-registry -o jsonpath='{.spec.clusterIP}')
docker exec $NODE sh -c "echo '$CIP suppline-registry.suppline.svc.cluster.local' >> /etc/hosts; mkdir -p /etc/containerd/certs.d/$REG"
docker cp registry-ca.crt $NODE:/etc/containerd/certs.d/$REG/ca.crt
docker exec $NODE sh -c "printf 'server = \"https://$REG\"\n[host.\"https://$REG\"]\n  capabilities = [\"pull\", \"resolve\"]\n  ca = \"/etc/containerd/certs.d/$REG/ca.crt\"\n' > /etc/containerd/certs.d/$REG/hosts.toml"
# containerd only reads certs.d when config_path is set; kind does not set it by default
docker exec $NODE sh -c "grep -q config_path /etc/containerd/config.toml || printf '\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n  config_path = \"/etc/containerd/certs.d\"\n' >> /etc/containerd/config.toml; systemctl restart containerd"

U=$(kubectl -n suppline get secret suppline-secrets -o jsonpath='{.data.SUPPLINE_REGISTRY_USERNAME}' | base64 -d)
P=$(kubectl -n suppline get secret suppline-secrets -o jsonpath='{.data.SUPPLINE_REGISTRY_PASSWORD}' | base64 -d)
for ns in my-app kyverno; do
  kubectl -n $ns create secret docker-registry mirror-pull --docker-server=$REG --docker-username="$U" --docker-password="$P"
done
kubectl -n my-app patch sa default -p '{"imagePullSecrets":[{"name":"mirror-pull"}]}'
```

**2. Kyverno: trust the certificate and use the secret.** Kyverno verifies attestations by reading the registry itself, so it needs the same trust and the same credentials. `credentials.allowInsecureRegistry` does not help: it only allows plain HTTP and still verifies TLS. Mount the CA into the admission controller (the value below adds it next to the system roots) and reference the secret from the policy:

```bash
kubectl -n kyverno create configmap suppline-registry-ca --from-file=registry-ca.crt
kubectl -n kyverno patch deploy kyverno-admission-controller --type json -p '[
 {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"registry-ca","configMap":{"name":"suppline-registry-ca"}}},
 {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"registry-ca","mountPath":"/extra-ca","readOnly":true}},
 {"op":"add","path":"/spec/template/spec/containers/0/env/-","value":{"name":"SSL_CERT_DIR","value":"/extra-ca"}}]'

kubectl patch imagevalidatingpolicy suppline-policy --type merge -p '{"spec":{"credentials":{"secrets":["mirror-pull"]}}}'
```

A Kyverno `helm upgrade` removes that patch; put the volume, mount and variable in the Kyverno chart values instead if you keep the cluster. Without the secret reference, admission fails with `UNAUTHORIZED: authentication required`.

**3. Use the full name for the rewrite.** Generate the rewrite policy against that name; the repositories are the same as under `suppline-registry:5000`:

```bash
curl -s -H "Authorization: Bearer change-me" \
  "http://localhost:8080/api/v1/integration/kyverno/mirror-rewrite?mirror=$REG&registries=docker.io,ghcr.io" | kubectl apply -f -
```

What this gave on that cluster, with `validationActions: [Deny]` and `pods_only=true` (images are in the table in step 3):

| Pod image requested | Pod ran | Reason |
|---|---|---|
| `busybox:1.36.1`, `redis:7-alpine`, `ghcr.io/jqlang/jq:1.7.1` | yes, from the mirror | rewritten, attested, `scanStatus: passed` |
| `nginx:1.27-alpine` | no, denied at admission | attestation says `scanStatus: failed` |
| `alpine:3.20`, never mirrored | no, denied | `MANIFEST_UNKNOWN` on the mirror |
| `quay.io/prometheus/node-exporter` | no, denied | registry outside the rewrite list, no attestation |
| Deployment of `redis:7-alpine` | yes | pods checked after the rewrite |
| Deployment of `nginx:1.27-alpine` | created, pods denied | `kubectl describe rs` shows the denial |

## If something does not work

| Symptom | Cause |
|---|---|
| The cluster never appears | The agent cannot reach suppline: `kubectl -n suppline logs deploy/clusterstate-agent`. It retries every 30 seconds. |
| Sync fails with `unauthorized` after a `helm upgrade` | Older charts regenerated the bundled registry's password on every upgrade, while the registry pod kept the old one. Restart the registry StatefulSet (`kubectl -n suppline rollout restart sts/suppline-registry`). Charts with the fix keep the password. |
| Kyverno reports `error`, not `fail` | It cannot read the image from the registry. The message names the cause: `x509: certificate signed by unknown authority` (trust the CA), `UNAUTHORIZED` (add `credentials.secrets`), `connection refused` to an address that is not your Service (see the next row), `MANIFEST_UNKNOWN` (the image is not on the mirror). |
| Kyverno or a pod resolves the registry to a LAN address | Your network's DNS search domain has a wildcard record. With Kubernetes' default `ndots:5` a name with fewer than five dots is tried against that domain before the real one. Set `dnsConfig.options: [{name: ndots, value: "1"}]` on the affected deployment, or fix the wildcard. |
| Every Deployment is rejected under `Deny` after you turned on the rewrite | The admission policy is checking the Deployment, which still names the upstream image. Regenerate it with `?pods_only=true` (step 6). |
| A pod is stuck in `ImagePullBackOff` on the mirror | The node cannot resolve, trust or authenticate to the registry. In a lab see [Lab only: use the bundled registry](#lab-only-use-the-bundled-registry); otherwise check the node's registry configuration and the pod's `imagePullSecrets`. |
| A running image is missing from the plan | The agent skips `kube-system`, `kube-public` and `kube-node-lease` by default (`excludedNamespaces`). |

[How suppline compares](COMPARISON.md) covers where it fits next to the tools you may already run.
