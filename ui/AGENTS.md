# AGENTS.md — suppline UI

> Quick-reference for AI coding agents working on the frontend. See also [../AGENTS.md](../AGENTS.md) for backend / project-wide context.

## What the UI is

A **vanilla HTML/CSS/ES-module SPA** — zero build step, no npm, no bundler. Served by `nginx:alpine` from a Docker container. Talks directly to the suppline REST API (`/api/v1`) via `fetch()`.

## File structure

```
ui/
├── index.html                      Single HTML shell (SPA entry point)
├── nginx.conf                      nginx server block
├── Dockerfile                      nginx:alpine image — copies static files + injects env at startup
├── test.js                         Node.js unit test entry point (no framework)
├── site.webmanifest                PWA manifest
│
├── css/
│   ├── main.css                    Global layout, nav, typography, spacing, responsive breakpoint
│   └── components.css              Cards, tables, badges, modals, toast notifications
│
├── js/
│   ├── main.js                     Bootstrap: config → APIClient → AuthManager → Router → register routes
│   ├── api.js                      APIClient — all fetch() calls; retry logic; 401 handling
│   ├── auth.js                     AuthManager — API key in localStorage, auth modal, logout
│   ├── router.js                   History API router — addRoute / navigate / handleRoute
│   │
│   ├── components/
│   │   ├── base-component.js       Base class: loadAndRender(), showLoading(), showError()
│   │   ├── common.js               LoadingSpinner, ErrorState, toast notifications, Modal.confirm()
│   │   ├── dashboard.js            Home: summary cards, vuln breakdown, expiry alerts, recent scans
│   │   ├── scans.js                Scans list with filter/sort/pagination
│   │   ├── scan-detail.js          Single scan view (extends scan-detail-base.js)
│   │   ├── scan-detail-base.js     Shared scan-detail rendering logic
│   │   ├── artifact-detail.js      Tag/digest detail within a repository
│   │   ├── repositories-list.js    Repository list with search, sort, pagination
│   │   ├── repository-detail.js    Per-repo tag list and scan history
│   │   ├── failed-images.js        ScansList pre-filtered to policy_passed=false
│   │   ├── vulnerabilities.js      CVE search across all images, grouped by CVE ID
│   │   ├── tolerations.js          Toleration list with expiry states (expired/expiring/active/inactive)
│   │   ├── integrations.js         Cosign public key + Kyverno ClusterPolicy export
│   │   ├── repositories-list.test.js
│   │   ├── repository-detail.test.js
│   │   └── test-runner.js          In-browser test runner
│   │
│   └── utils/
│       ├── security.js             escapeHtml() — XSS protection (DOM textContent, not regex)
│       ├── date.js                 parseTimestamp(), formatDate(), formatRelativeTime(), isPast(), daysUntil()
│       ├── severity.js             getSeverityBadge(), getSeverityColor(), truncateDigest()
│       └── helpers.js              confirmDialog(), buildQueryString(), debounce(), copyToClipboard()
│
└── docker-entrypoint.d/
    └── 40-inject-env.sh            Writes /config.json from $API_BASE_URL at container start
```

## Client-side routes

| Path | Component |
|---|---|
| `/` | `Dashboard` |
| `/repositories` | `RepositoriesList` |
| `/repositories/:name` | `RepositoryDetail` |
| `/repositories/:name/tags/:digest` | `ArtifactDetail` |
| `/scans` | `ScansList` |
| `/scans/:digest` | `ScanDetail` |
| `/failed` | `FailedImages` |
| `/vulnerabilities` | `Vulnerabilities` |
| `/tolerations` | `Tolerations` |
| `/tolerations/expiring` | `Tolerations` (pre-filtered) |
| `/integrations` | `Integrations` |

nginx uses `try_files $uri $uri/ /index.html` so deep-links work on reload.

## API communication

- `APIClient` (`js/api.js`) loads `baseURL` from `/config.json` (`apiBaseURL` field) at startup
- `fetch()` with `mode: 'cors'`, `credentials: 'omit'`
- Auth: `Authorization: Bearer <apiKey>` — key stored in `localStorage` under key `stk_api_key`
- Retries: up to 3 attempts with exponential backoff on network errors
- 401 → `AuthManager.handle401()` clears key and shows auth modal
- Pagination: `limit`/`offset` query params; totals from `X-Total-Count` response header

## Authentication

- API key entered by user at runtime → stored in `localStorage` (`stk_api_key`)
- Validated against the backend at login (any 401 re-shows the modal)
- **No auth baked into the image** — key is purely runtime state

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `API_BASE_URL` | **Yes** | Backend API origin injected into `/config.json` by `40-inject-env.sh` at container start. If unset, app falls back to `window.location.origin`. |

No other env vars. All other config is user-supplied at runtime.

## Build & deploy

**No build step.** Files are static — copy and serve.

```bash
# Build image
docker build -t suppline-ui ./ui

# Run locally (adjust API URL)
docker run -p 3000:80 -e API_BASE_URL=http://localhost:8080 suppline-ui
```

Or via the project root:
```bash
make build-ui    # docker build -t suppline-ui:latest -f ui/Dockerfile ./ui
```

`/config.json` is generated at container start by `docker-entrypoint.d/40-inject-env.sh` — **never commit it**.

## CSS design system

Defined as CSS custom properties on `:root` in `css/main.css`:
- **Colors**: via `--color-*` variables; severity palette: Critical=`#dc2626`, High=`#f97316`, Medium=`#eab308`, Low=`#3b82f6`
- **Spacing scale**: `--spacing-xs` through `--spacing-2xl`
- **Responsive**: single breakpoint at `768px` (collapses nav)
- Severity logic lives in `js/utils/severity.js` — severity strings must be **uppercase** (`CRITICAL`, `HIGH`, etc.) to match API responses

## Testing

```bash
node ui/test.js   # run Node.js unit tests for component logic
```

- Hand-rolled assertions — no test framework dependency
- `MockApiClient` stubs all API calls
- In-browser test runner available at `js/components/test-runner.js`
- Co-located `*.test.js` files for components

## Security rules — must follow

- **Always use `escapeHtml()`** from `js/utils/security.js` whenever API/user data is interpolated into an HTML string. It is the sole XSS defence.
- **Never bypass CSP** — the `<meta>` CSP in `index.html` includes SHA-256 hashes for the only two permitted inline styles. If you add/change an inline style, you must recompute and update its hash.
- **nginx security headers** are set in `nginx.conf`: `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection`. Do not remove them.
- **No caching** of HTML or any asset (`Cache-Control: no-store`) — do not change this.
- API timestamps are **Unix seconds (int64)** — `js/utils/date.js` multiplies by 1000 before passing to `Date`. Keep this consistent.

## Common pitfalls

- **No npm / no build** — do not introduce a bundler, package.json, or build step.
- **`/config.json` is runtime-generated** — never import it statically or assume it exists during development outside Docker.
- **nginx does not proxy the backend** — the browser talks directly to `API_BASE_URL`; CORS is resolved on the suppline server side.
- **Severity badge/color logic** is centralised in `js/utils/severity.js` — add any new severity rendering there, not inline in components.
