# Suppline UI

This directory contains the frontend web application for Suppline.

## Structure

- `index.html` - Main HTML entry point
- `css/` - Stylesheets
- `js/` - JavaScript application code
- `nginx.conf` - Nginx configuration for serving the application
- `Dockerfile` - Container image definition

## Development

This is a static web application using vanilla HTML, CSS, and JavaScript. No build process is required for development.

To run locally with Docker:

```bash
docker build -t suppline-ui .
docker run -p 8081:80 -e API_BASE_URL=http://localhost:8080 suppline-ui
```

## Configuration

The application reads its API base URL from `/config.json`, which is generated at container startup from the `API_BASE_URL` environment variable.
