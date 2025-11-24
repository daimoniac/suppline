#!/bin/sh
set -e

TEMPLATE_FILE="/etc/nginx/conf.d/default.conf.template"
OUTPUT_FILE="/etc/nginx/conf.d/default.conf"
CONFIG_JSON="/usr/share/nginx/html/config.json"

# Generate config.json for frontend
echo "Generating $CONFIG_JSON with API_BASE_URL=$API_BASE_URL"
echo "{\"apiBaseURL\": \"$API_BASE_URL\"}" > "$CONFIG_JSON"

if [ -f "$TEMPLATE_FILE" ]; then
    # Check if output file exists and is not writable (e.g. mounted read-only)
    if [ -f "$OUTPUT_FILE" ] && [ ! -w "$OUTPUT_FILE" ]; then
        echo "Output file $OUTPUT_FILE exists and is read-only. Skipping template injection."
    else
        echo "Injecting API_BASE_URL: $API_BASE_URL"
        envsubst '${API_BASE_URL}' < "$TEMPLATE_FILE" > "$OUTPUT_FILE"
        echo "Nginx configuration injected successfully"
    fi
else
    echo "Template file $TEMPLATE_FILE not found. Skipping template injection."
fi
