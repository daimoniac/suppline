---
layout: default
title: suppline - Container Supply Chain Security
---

# suppline

*Self-hosted image intake gateway for Kubernetes.*

Continuously mirrors remote registries, scans, policy-gates, and attests images before they reach your cluster.

## What is suppline?

suppline mirrors images from public registries into your local registry, continuously scans them with Trivy, evaluates CEL-based security policies, and publishes Sigstore attestations. Clusters then pull only from the local mirror and can enforce "verified-only" deployments via Kyverno/OPA.

**Mirror → Scan → Gate → Attest → Run.**

Cloud native, one service, no SaaS dependency — air-gap compatible by design.

## Key Features

- **Continuous Registry Mirroring** - Syncs images from public registries to your local mirror
- **Vulnerability Scanning** - Runs Trivy to identify vulnerabilities and generate SBOMs
- **Policy Engine** - CEL-based policies with CVE toleration support
- **Sigstore Attestations** - Creates signed attestations via Cosign
- **State Persistence** - SQLite-based scan history and vulnerability tracking
- **REST API** - Query results, trigger rescans, manage policies
- **Observability** - Prometheus metrics, structured JSON logs, health checks
- **Air-Gap Compatible** - No external registry dependencies

## Quick Start

### 1. Configure

```bash
cp suppline.yml.example suppline.yml
```

Edit `suppline.yml` with your registry credentials and mirroring rules.

### 2. Generate Keys

```bash
mkdir -p keys
cosign generate-key-pair
mv cosign.key keys/
```

### 3. Start

```bash
docker compose up -d
```

### 4. Verify

```bash
curl http://localhost:8081/health
curl http://localhost:8080/api/v1/scans
```

## Documentation

- [Configuration Guide](CONFIGURATION.md) - Environment variables and configuration format
- [Policy Guide](POLICY.md) - CEL policy examples and reference
- [GitHub Repository](https://github.com/daimoniac/suppline)

## Why Mirror?

- **Increased Availability** - Clusters pull from your local registry, not external vendors
- **Decreased Vendor Dependency** - Your supply chain is no longer tied to public registry availability
- **Improved Supply Chain Security** - All images pass through your security pipeline before reaching clusters
- **Air-Gap Deployments** - Mirror images once, deploy to isolated networks
- **Compliance & Audit** - Complete audit trail in your local database
- **Cost Optimization** - Reduce egress bandwidth

## Architecture

```
Remote Registries → Mirroring (regsync) → Local Registry
                                              ↓
                                          Watcher → Queue → Worker → Scanner (Trivy)
                                                                          ↓
                                                                  Policy Engine
                                                                          ↓
                                                                  Attestor (Cosign)
                                                                          ↓
                                                                  State Store (SQLite)
```

## Support

- **Issues**: [GitHub Issues](https://github.com/daimoniac/suppline/issues)
- **Examples**: See `suppline.yml.example` and deployment guides
