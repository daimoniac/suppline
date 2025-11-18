FROM nginx:alpine

# Install gettext for envsubst
RUN apk add --no-cache gettext

# Copy web application files
COPY . /usr/share/nginx/html

# Copy nginx configuration template
COPY nginx.conf /etc/nginx/conf.d/default.conf.template

# Set environment variable with default value
ENV API_BASE_URL=http://localhost:8080

# Copy entrypoint script
COPY docker-entrypoint.d/40-inject-env.sh /docker-entrypoint.d/40-inject-env.sh
RUN chmod +x /docker-entrypoint.d/40-inject-env.sh && \
    chown -R nginx:nginx /usr/share/nginx/html

# Expose port 80
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:80/ || exit 1

# Use default nginx entrypoint
