# frontend/

The PhishShield dashboard: a Vite + React 19 + TypeScript + Tailwind 4 single-page app. The
Express server in the repo root serves this app's `dist/` at `/` with an SPA fallback, so the UI
and the API share one origin.

## Scripts

- `npm run build` — production build into `dist/` (the root `npm run build` does this too)
- `npm run dev` — Vite dev server with HMR; proxies `/api` to Express on `:3000`
- `npm test` — vitest (jsdom)
- `npm run typecheck` / `npm run lint` / `npm run format`

## Conventions

- Tailwind 4 tokens live in `src/styles.css`. Use the semantic utilities (`bg-card`,
  `text-muted-foreground`, `border-border`) and the component classes already defined there
  (`panel`, `panel-glow`, `row-panel`, `chart-bg`, `grid-bg`, `pill-glow`) rather than raw colors.
- Reach the backend through `src/lib/api.ts`; derive dashboard numbers with the pure helpers in
  `src/lib/threat-stats.ts` (unit-tested) instead of inline arithmetic.
- `src/components/ui/` is the shadcn/radix kit.
- The markup in `src/pages/Dashboard.tsx` and `src/components/ui/` was carried over byte-for-byte
  from the original design — prefer adding around it over restructuring it.
- `src/lib/engine.ts` is a client-side evaluation of the detection heuristics, kept for reference
  and tests only. The backend engine is the source of truth.
