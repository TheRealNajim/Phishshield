# PhishShield dashboard

The PhishShield front end: a Vite + React 19 + TypeScript + Tailwind 4 single-page app. The
Express server in `backend/` serves this app's `dist/` at `/` with an SPA fallback, so the UI
and the API share one origin.

## Run it

```sh
npm install
npm run build   # -> dist/, served by `npm start` in `backend/`
npm run dev     # Vite dev server with HMR; proxies /api to http://127.0.0.1:3000
```

For local development run the API as well (`npm start` in `backend/`) — `npm run dev` proxies
`/api` to it. Nothing else needs configuring: the client calls same-origin `/api/...`.

## What's here

| Path | Purpose |
| --- | --- |
| `src/main.tsx` | entry point: React root + query client provider |
| `src/pages/Dashboard.tsx` | the dashboard: stats, severity split, 7-day trend, recent verdicts |
| `src/components/scan-panel.tsx` | file/email scans with verdict, reasons, IOCs and agent code |
| `src/components/app-boundary.tsx` | error boundary + not-found page |
| `src/lib/api.ts` | typed client for the Express API |
| `src/lib/threat-stats.ts` | pure stat derivations (unit-tested) |
| `src/components/ui/` | shadcn/radix component kit |

## Scripts

| Script | What it does |
| --- | --- |
| `npm run dev` | Vite dev server + HMR, `/api` proxied to Express on `:3000` |
| `npm run build` | production build into `dist/` |
| `npm run preview` | serve the built `dist/` on its own (API calls will 404) |
| `npm test` | vitest (jsdom): stat helpers, render tests, scan flow |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run lint` | eslint (includes prettier) |
| `npm run format` | prettier --write |

## Data flow

- `GET /api/analyze/history` — verdicts behind the stat cards, severity split, trend and table
- `GET /api/health` — mock sandbox vs live micro-VM indicator in the header
- `GET /api/billing` — the Teams upgrade card
- `POST /api/analyze` (or `/api/analyze/deep`) — the scan panel; `GET /samples/*.eml` fills the
  sample buttons

## Built with

- Vite, React 19, TypeScript, Tailwind CSS 4
- TanStack Query (data fetching), lucide-react (icons), shadcn/radix components
