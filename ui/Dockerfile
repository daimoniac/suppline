FROM nginx:alpine

# Install gettext for envsubst
RUN apk add --no-cache gettext

# Copy web application files
COPY . /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Set environment variable with default value
ENV API_BASE_URL=http://localhost:8080

# Remove any old entrypoint scripts that might conflict
RUN rm -f /docker-entrypoint.d/40-generate-config.sh

# Create entrypoint script to substitute environment variables
RUN echo '#!/bin/sh' > /docker-entrypoint.d/40-inject-env.sh && \
    echo 'set -e' >> /docker-entrypoint.d/40-inject-env.sh && \
    echo 'echo "Injecting API_BASE_URL: $API_BASE_URL"' >> /docker-entrypoint.d/40-inject-env.sh && \
    echo 'export ENV_API_BASE_URL="$API_BASE_URL"' >> /docker-entrypoint.d/40-inject-env.sh && \
    echo 'envsubst '\''$ENV_API_BASE_URL'\'' < /usr/share/nginx/html/index.html.template > /usr/share/nginx/html/index.html' >> /docker-entrypoint.d/40-inject-env.sh && \
    echo 'echo "Environment variables injected successfully"' >> /docker-entrypoint.d/40-inject-env.sh && \
    chmod +x /docker-entrypoint.d/40-inject-env.sh && \
    mv /usr/share/nginx/html/index.html /usr/share/nginx/html/index.html.template && \
    chown -R nginx:nginx /usr/share/nginx/html

# Expose port 80
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:80/ || exit 1

# Use default nginx entrypoint
