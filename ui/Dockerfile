FROM nginx:alpine

# Copy web application files
COPY . /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Set environment variable with default value
ENV API_BASE_URL=http://localhost:8080

# Create config.json at runtime with the API_BASE_URL
RUN echo '#!/bin/sh' > /docker-entrypoint.d/40-generate-config.sh && \
    echo 'echo "{\"apiBaseURL\": \"$API_BASE_URL\"}" > /usr/share/nginx/html/config.json' >> /docker-entrypoint.d/40-generate-config.sh && \
    chmod +x /docker-entrypoint.d/40-generate-config.sh

# Expose port 80
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:80/ || exit 1

# Use default nginx entrypoint
