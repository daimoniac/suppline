# Suppline Helm Chart

This Helm chart deploys Suppline, a supply chain security scanner, to a Kubernetes cluster.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- PV provisioner support in the underlying infrastructure (if persistence is enabled)

## Installing the Chart

To install the chart with the release name `suppline`:

```bash
helm install suppline ./charts/suppline
```

To install with custom values:

```bash
helm install suppline ./charts/suppline -f my-values.yaml
```

## Uninstalling the Chart

To uninstall/delete the `suppline` deployment:

```bash
helm uninstall suppline
```

## Configuration

The following table lists the configurable parameters of the Suppline chart and their default values.

### Global Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.namespace` | Namespace for deployment | `suppline` |

### Backend Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `backend.replicaCount` | Number of backend replicas | `1` |
| `backend.image.repository` | Backend image repository | `suppline` |
| `backend.image.tag` | Backend image tag | `latest` |
| `backend.image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `backend.service.type` | Service type | `ClusterIP` |
| `backend.service.port` | API service port | `8080` |
| `backend.service.metricsPort` | Metrics service port | `9090` |
| `backend.service.healthPort` | Health check port | `8081` |
| `backend.resources.requests.memory` | Memory request | `512Mi` |
| `backend.resources.requests.cpu` | CPU request | `500m` |
| `backend.resources.limits.memory` | Memory limit | `1Gi` |
| `backend.resources.limits.cpu` | CPU limit | `1000m` |
| `backend.supplineConfig` | Suppline configuration (suppline.yml content) | See values.yaml |
| `backend.attestationKey.enabled` | Enable attestation signing | `true` |
| `backend.attestationKey.key` | Base64 encoded cosign key | `""` |
| `backend.attestationKey.password` | Cosign key password | `""` |

### Trivy Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `trivy.image.repository` | Trivy image repository | `aquasec/trivy` |
| `trivy.image.tag` | Trivy image tag | `0.58.2` |
| `trivy.resources.requests.memory` | Memory request | `1Gi` |
| `trivy.resources.limits.memory` | Memory limit | `2Gi` |

### Frontend Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `frontend.enabled` | Enable frontend deployment | `true` |
| `frontend.replicaCount` | Number of frontend replicas | `2` |
| `frontend.image.repository` | Frontend image repository | `nginx` |
| `frontend.image.tag` | Frontend image tag | `alpine` |
| `frontend.apiBaseURL` | Backend API URL for frontend | `http://suppline:8080` |
| `frontend.ingress.enabled` | Enable ingress | `false` |
| `frontend.ingress.className` | Ingress class name | `""` |
| `frontend.ingress.hosts` | Ingress hosts configuration | See values.yaml |

### Persistence Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `persistence.data.enabled` | Enable data persistence | `true` |
| `persistence.data.size` | Data volume size | `10Gi` |
| `persistence.data.storageClassName` | Storage class name | `""` |
| `persistence.trivyCache.enabled` | Enable Trivy cache persistence | `true` |
| `persistence.trivyCache.size` | Trivy cache volume size | `5Gi` |

### RBAC Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.name` | Service account name | `suppline` |
| `rbac.create` | Create RBAC resources | `true` |

## Example: Custom Configuration

Create a `my-values.yaml` file:

```yaml
backend:
  image:
    repository: myregistry.example.com/suppline
    tag: "v1.0.0"

frontend:
  enabled: true
  ingress:
    enabled: true
    className: nginx
    hosts:
      - host: suppline.example.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: suppline-tls
        hosts:
          - suppline.example.com

persistence:
  data:
    storageClassName: fast-ssd
    size: 20Gi
```

Then install:

```bash
helm install suppline ./charts/suppline -f my-values.yaml
```

## Upgrading

To upgrade an existing release:

```bash
helm upgrade suppline ./charts/suppline -f my-values.yaml
```

## Notes

- The backend uses SQLite by default, which requires `ReadWriteOnce` access mode and only supports a single replica
- For production deployments, consider using a different database backend that supports multiple replicas
- Make sure to update the `supplineConfig` with your actual registry credentials and sync configuration
- The Trivy sidecar container requires significant memory for vulnerability database updates

## Support

For issues and questions, please visit: https://github.com/yourusername/suppline
