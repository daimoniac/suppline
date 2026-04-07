# AGENTS.md — suppline UI

> Quick-reference for AI coding agents working on the frontend. Read this before starting any task.

## Tech stack

| Concern | Technology |
|---|---|
| Framework | React 19 (StrictMode) |
| Language | TypeScript 5.9 (strict mode) |
| Build tool | Vite 8 |
| Styling | Tailwind CSS 4 (CSS-first config via `@tailwindcss/vite` — **no `tailwind.config.js`**) |
| Routing | React Router DOM v7 (BrowserRouter + nested routes) |
| Icons | lucide-react |
| HTTP | Native `fetch` — no axios, no React Query |
| State | Local `useState`/`useEffect` per page + React Context for auth/toast |
| Lint | ESLint 9 (flat config), typescript-eslint, react-hooks, react-refresh plugins |
| Runtime | nginx:alpine serving static assets built from `dist/` |

## Essential commands

```bash
npm run dev       # Vite dev server with HMR + proxy to localhost:8080
npm run build     # tsc -b && vite build  (type-check then bundle → dist/)
npm run lint      # ESLint across all .ts/.tsx
npm run preview   # Serve production build locally

# Docker
docker build -t suppline-ui ui/
docker run -p 3000:80 -e API_BASE_URL=http://localhost:8080 suppline-ui
```

## Project layout

```
ui/
├── index.html                    # SPA shell; mounts <div id="root">; imports Inter font
├── vite.config.ts                # Dev proxy: /api + /health + /config.json → localhost:8080
├── nginx.conf                    # nginx template; SPA fallback; security headers; asset caching
├── Dockerfile                    # Multi-stage: node:22-alpine build → nginx:alpine serve
├── docker-entrypoint.d/
│   └── 40-inject-env.sh         # Generates /config.json at container start; injects $API_BASE_URL
└── src/
    ├── main.tsx                  # ReactDOM.createRoot entry
    ├── App.tsx                   # BrowserRouter + providers + route tree
    ├── index.css                 # Tailwind @import + @theme design tokens + base resets + animations
    ├── lib/
    │   ├── api.ts                # APIClient class + ALL TypeScript domain types
    │   ├── auth.tsx              # AuthContext + AuthProvider + useAuth hook
    │   ├── toast.tsx             # ToastContext + ToastProvider + useToast hook
    │   └── utils.ts              # Pure helpers: escapeHtml, format*, severity*, cn, copyToClipboard
    ├── components/
    │   ├── Layout.tsx            # Sidebar + <Outlet> shell for all authenticated routes
    │   └── ui.tsx                # All shared UI primitives (see below)
    └── pages/
        ├── LoginPage.tsx
        ├── DashboardPage.tsx
        ├── RepositoriesPage.tsx
        ├── RepositoryDetailPage.tsx
        ├── ScansPage.tsx
        ├── ScanDetailPage.tsx
        ├── FailedImagesPage.tsx
        ├── VulnerabilitiesPage.tsx
        ├── VEXPage.tsx
        └── IntegrationsPage.tsx
```

## Routing

All routes live in `src/App.tsx`. The app renders `<LoginPage />` full-screen when unauthenticated; otherwise all pages render inside `<Layout>` (sidebar shell with `<Outlet />`).

```
/                              → DashboardPage
/repositories                  → RepositoriesPage
/repositories/:name            → RepositoryDetailPage
/repositories/:name/tags/:digest → ScanDetailPage  (repo-centric)
/scans                         → ScansPage
/scans/:digest                 → ScanDetailPage     (scan-centric)
/failed                        → FailedImagesPage
/vulnerabilities               → VulnerabilitiesPage
/vex                           → VEXPage
/tolerations                   → redirect to /vex
/integrations                  → IntegrationsPage
*                              → redirect to /
```

- No lazy loading — all pages eagerly imported.
- `ScanDetailPage` is shared by two URL shapes; it distinguishes them via `!!useParams().name`.
- Always use `encodeURIComponent` when interpolating repo names or digests into `useNavigate`/`<Link>` paths.

## API client (`src/lib/api.ts`)

`APIClient` is a class instantiated once by `AuthContext` and passed down via `useAuth().apiClient`.

- **Base URL**: defaults to `''` (same-origin). nginx proxies `/api/*` to the Go backend. In dev, Vite proxies the same.
- **Auth**: Every request sends `Authorization: Bearer <key>`. Key stored in `localStorage` under `stk_api_key`.
- **Retry**: `TypeError` (network failure) retried up to 3 times with 1 s / 2 s / 3 s backoff. HTTP errors (`APIError`) are **not** retried.
- **Pagination**: large lists (`/repositories`, `/vulnerabilities`) use `limit` + `offset` query params and read `X-Total-Count` from the response header. Use `requestWithResponse` for those.
- **Downloads**: `requestText` is used for plain-text responses (PEM keys, YAML policy files).
- **`qs(filters)`**: private helper to build `URLSearchParams`. Pass filter/sort/page objects through it.

**All TypeScript domain types live in `api.ts`** — no separate `types/` directory:  
`Scan`, `ScanDetail`, `Vulnerability`, `AppliedVEXStatement`, `VulnerabilityGroup`, `VulnCount`, `Repository`, `RepositoriesResponse`, `RepositoryTag`, `RepositoryDetailResponse`, `RepositoryVEXInfo`, `VEXSummary`

Backend JSON field names are **PascalCase** (`Digest`, `PolicyPassed`, `CriticalVulnCount`, etc.) — direct JSON deserialisation of Go struct tags. Match them exactly.

## Shared UI primitives (`src/components/ui.tsx`)

Never reach for an external component library. All UI building blocks are here:

| Export | Purpose |
|---|---|
| `StatusBadge` | Green "Passed" / red "Failed" pill |
| `SeverityBadge` | Coloured severity pill with optional count |
| `VulnCounts` | Row of `SeverityBadge` for all severities |
| `LoadingState` | Centred spinner with message |
| `EmptyState` | Icon + title + message for zero-data views |
| `ErrorState` | Error icon + message + optional Retry button |
| `SortHeader` | `<th>` with chevron sort indicator |
| `Pagination` | First/prev/next/last buttons + item count |
| `ConfirmModal` | Backdrop modal with Confirm/Cancel |
| `PageHeader` | `<h1>` title + `<p>` subtitle |

Use these everywhere. Do not create one-off replacements.

## Page component pattern

All pages follow the same structure. Do not deviate from it:

```tsx
export default function XxxPage() {
  const { apiClient } = useAuth();
  const { toast } = useToast();
  const [data, setData] = useState<SomeType[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // ... filter/sort/page state

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await apiClient.getSomething(filters);
      setData(result);
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  }, [apiClient, /* filter deps */]);

  useEffect(() => { load(); }, [load]);

  if (loading && !data.length) return <LoadingState message="Loading..." />;
  if (error) return <ErrorState message={error} onRetry={load} />;
  return <div>...</div>;
}
```

- Default export, one component per file.
- Get `apiClient` from `useAuth()`, not by constructing a new instance.
- Show `<LoadingState>` only on initial load (when data is empty). For refreshes, let stale data stay visible.
- Show `<ErrorState>` with an `onRetry={load}` prop.
- Use `<ConfirmModal>` before any destructive or expensive action.

## State management

**No global state library.** Keep state local unless it truly needs to be shared.

| Scope | Mechanism |
|---|---|
| Authentication | `AuthContext` (`isAuthenticated`, `apiClient`, `login`, `logout`) |
| Toasts | `ToastContext` (`toast(message, type)`) — auto-dismissed after 4 s |
| Page data | Local `useState` per page — no cross-page cache, re-fetched on mount |
| URL-driven filters | `useSearchParams` for filter/sort/page state that should survive navigation |

Do not add Zustand, Redux, Jotai, or any other state library.

## Styling

**Tailwind CSS 4 — CSS-first.** There is no `tailwind.config.js`. All design tokens live in `src/index.css` inside `@theme { ... }`. When you need a new colour or size token, add it there.

Design token reference:

```
bg-surface           #0f0f0f   (outermost background)
bg-bg-primary        #171717   (main content background)
bg-bg-secondary      #1e1e1e   (cards, panels)
bg-bg-tertiary       #262626   (nested surfaces)
border-border        #2e2e2e
border-border-hover  #404040
text-text-primary    #ededed
text-text-secondary  #a0a0a0
text-text-muted      #666
text-accent / bg-accent        #3ecf8e  (primary action colour)
text-accent-hover              #2db67b
text-danger / bg-danger        #ef4444
text-warning / bg-warning      #f59e0b
text-info / bg-info            #3b82f6
text-success / bg-success      #3ecf8e
bg-severity-critical           #ef4444
bg-severity-high               #f97316
bg-severity-medium             #eab308
bg-severity-low                #6b7280
bg-severity-exempted           #8b5cf6
```

This is a **dark-only UI** — no light mode. Do not add light-mode variants.

Use `cn(...classes)` from `src/lib/utils.ts` for conditional class merging (like `clsx`).

Severity colours have dedicated helpers in `utils.ts` — use `severityColor()` and `severityTextColor()` rather than hardcoding colour strings.

## Utility helpers (`src/lib/utils.ts`)

| Function | Purpose |
|---|---|
| `escapeHtml(s)` | HTML-escape for raw string injection (see Security below) |
| `formatDate(ts)` | Format Unix timestamp (seconds or ms) to locale string |
| `formatRelativeTime(ts)` | "2 hours ago" style; normalises s vs ms timestamps |
| `formatDuration(ms)` | "1m 23s" from milliseconds |
| `severityColor(s)` | Tailwind bg class for severity string |
| `severityTextColor(s)` | Tailwind text class for severity string |
| `cn(...classes)` | Conditional class merging |
| `copyToClipboard(text)` | Returns `Promise<boolean>` |

Timestamp handling: the backend returns some timestamps as Unix **seconds** (`< 1e12`) and others as Unix **milliseconds** (`>= 1e12`). All `format*` helpers normalise this — use them instead of manual `new Date()` calls.

## Security

- **React JSX automatically escapes** all dynamic values in JSX children. You do not need `escapeHtml()` for normal JSX rendering.
- **Never use `dangerouslySetInnerHTML`** with unsanitised API data. If you must set raw HTML, call `escapeHtml()` first.
- **`encodeURIComponent`** must be used when interpolating user-controlled strings (repo names, digests, CVE IDs) into URL paths or query strings.
- **No XSS via `innerHTML`** — avoid `element.innerHTML = apiData` anywhere in the UI.
- nginx sets `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection: 1; mode=block` — do not remove these from `nginx.conf`.
- API key is stored in `localStorage` (`stk_api_key`). Do not log it or expose it in the DOM.

## Code conventions

- **Named exports** for everything in `lib/` and `components/ui.tsx`.
- **Default exports** for all page components and `Layout`.
- **`catch (e: unknown)`** — never use untyped `catch (e)`. Pattern: `e instanceof Error ? e.message : 'Failed'`.
- **`useCallback` on `load`** so `useEffect(() => { load(); }, [load])` doesn't create infinite loops.
- **`eslint-disable-next-line react-hooks/exhaustive-deps`** only when truly intentional (e.g. "fetch once on mount with no changing deps"). Add a comment explaining why.
- **Client-side sort/filter** for small, fully-loaded datasets. **Server-side pagination** (`limit`/`offset`) for large lists (repositories, vulnerabilities).
- Do not add new external dependencies without strong justification. The existing `fetch`-based API client and Tailwind primitives cover almost all needs.
- TypeScript strict mode is on. Fix all type errors — do not use `any` or `@ts-ignore`.

## Adding a new page

1. Create `src/pages/NewThingPage.tsx` using the page pattern above.
2. Add the route to `src/App.tsx` inside the `<Route element={<Layout />}>` block.
3. Add a `<NavLink>` entry to the sidebar in `src/components/Layout.tsx`.
4. Add any new API methods + types to `src/lib/api.ts`.
5. Use existing primitives from `components/ui.tsx` — add new ones there only if genuinely reusable.

## Adding a new shared UI component

Add it as a named export to `src/components/ui.tsx`. Keep it stateless and Tailwind-only.

## Adding a new API method

Add it to the `APIClient` class in `src/lib/api.ts`. Add the corresponding TypeScript type(s) in the same file. Follow the existing patterns:
- Use `request<T>` for simple calls.
- Use `requestWithResponse<T>` when you need response headers (e.g. `X-Total-Count`).
- Use `requestText` for plain-text / binary downloads.
- Build query strings with `this.qs(filters)`.

## Common pitfalls

- **No `tailwind.config.js`** — Tailwind 4 is configured entirely through `src/index.css`. Adding a config file will conflict.
- **No test script** — there is no `npm test`. The `test.js` in the repo root references the older plain-JS codebase. If adding tests, use Vitest (compatible with Vite) and add a `test` script to `package.json`.
- **Backend JSON is PascalCase** — `response.Digest`, not `response.digest`. Check Go struct JSON tags before writing a new type.
- **Severity helpers are the single source of truth** — never hardcode colour strings for severity inside a page or component; always go through `severityColor()` / `severityTextColor()` in `utils.ts`.
- **No global API client** — always get `apiClient` from `useAuth()`. Do not import and instantiate `APIClient` directly in a component.
- **`/config.json`** is generated at container startup by `docker-entrypoint.d/40-inject-env.sh`. In dev, Vite proxies it from the backend. Do not commit a `config.json` file.
