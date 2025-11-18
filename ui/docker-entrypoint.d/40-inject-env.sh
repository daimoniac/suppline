#!/bin/sh
set -e

echo "Injecting API_BASE_URL: $API_BASE_URL"
envsubst '${API_BASE_URL}' < /etc/nginx/conf.d/default.conf.template > /etc/nginx/conf.d/default.conf
echo "Nginx configuration injected successfully"
