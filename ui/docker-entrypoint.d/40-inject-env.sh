#!/bin/sh
set -e

TEMPLATE_FILE="/etc/nginx/conf.d/default.conf.template"
OUTPUT_FILE="/etc/nginx/conf.d/default.conf"
CONFIG_JSON="/usr/share/nginx/html/config.json"

# Browser-facing API base (often relative "/api" behind same-origin nginx/ingress).
# NOTE: should be a base URL without a trailing /api path when absolute.
API_BASE_URL="${API_BASE_URL:-/api}"

# Upstream for nginx proxy_pass (must be an absolute http(s) URL).
BACKEND_URL="${BACKEND_URL:-$API_BASE_URL}"

echo "Generating $CONFIG_JSON with API_BASE_URL=$API_BASE_URL"
echo "{\"apiBaseURL\": \"$API_BASE_URL\"}" > "$CONFIG_JSON"

if [ -f "$TEMPLATE_FILE" ]; then
    if [ -f "$OUTPUT_FILE" ] && [ ! -w "$OUTPUT_FILE" ]; then
        echo "Output file $OUTPUT_FILE exists and is read-only. Skipping template injection."
    else
        echo "Injecting BACKEND_URL=$BACKEND_URL into nginx config"
        # shellcheck disable=SC2016
        envsubst '${BACKEND_URL}' < "$TEMPLATE_FILE" > "$OUTPUT_FILE"
        echo "Nginx configuration injected successfully"
    fi
else
    echo "Template file $TEMPLATE_FILE not found. Skipping template injection."
fi
