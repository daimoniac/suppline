#!/bin/bash
set -e

# Deploy with Helm
echo "Deploying suppline with Helm..."

# Check if values-secrets.yaml exists
if [ -f charts/suppline/values-secrets.yaml ]; then
    echo "Using values-secrets.yaml for secrets..."
    helm upgrade --install suppline ./charts/suppline \
        -f charts/suppline/values.yaml \
        -f charts/suppline/values-secrets.yaml
else
    echo "No values-secrets.yaml found!"
fi
