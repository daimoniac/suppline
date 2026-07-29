# Build stage
FROM node:24-alpine3.24 AS builder

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install

COPY . .
RUN npm run build

# Serve stage
FROM nginx:1.31.3-alpine3.24

# Remove default nginx static assets; directory must be writable by nginx (config.json)
RUN rm -rf /usr/share/nginx/html/* \
 && chown nginx:nginx /usr/share/nginx/html

# Copy built assets (nginx user must own html so runtime can write config.json)
COPY --from=builder --chown=nginx:nginx /app/dist /usr/share/nginx/html

# Copy nginx config template (writable for envsubst at start)
COPY --chown=nginx:nginx nginx.conf /etc/nginx/conf.d/default.conf.template

# Copy environment injection script
COPY --chown=nginx:nginx docker-entrypoint.d/40-inject-env.sh /docker-entrypoint.d/40-inject-env.sh
RUN chmod +x /docker-entrypoint.d/40-inject-env.sh \
 && chown -R nginx:nginx /usr/share/nginx/html /etc/nginx/conf.d /var/cache/nginx /var/log/nginx \
 && touch /var/run/nginx.pid && chown nginx:nginx /var/run/nginx.pid

EXPOSE 80
