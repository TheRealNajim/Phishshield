# PhishShield — hackathon MVP

Agent that writes + runs its own Python in a CreateOS sandbox to verdict sketchy files/emails.
Free for individuals, Teams ($19/mo) for staff inbox protection.

## Run locally (mock sandbox, no keys)
```
cd phishshield
npm install
npm --prefix frontend install
Copy-Item .env.example .env
npm run build   # builds frontend/ -> frontend/dist (Express serves it)
npm test        # 22 checks: engine + analyze/deep/report/share/billing API + py parity
npm start
# open http://127.0.0.1:3000
```

## Frontend (`frontend/`)
The dashboard is a Vite + React 19 + TypeScript + Tailwind 4 app (shadcn/radix components included).
`server.js` serves `frontend/dist` at `/` with an SPA fallback, so the API and UI share one origin.

```
npm run build                     # build the dashboard (also: npm --prefix frontend run build)
npm --prefix frontend run dev     # Vite dev server with HMR; proxies /api to Express on :3000
npm --prefix frontend test        # vitest: stats helpers, render + scan-flow tests
npm --prefix frontend run typecheck
```
- `src/pages/Dashboard.tsx` — the dashboard: stats, severity split, 7-day trend and recent verdicts come from `GET /api/analyze/history`; sandbox mode from `/api/health`; the upgrade card from `/api/billing`.
- `src/components/scan-panel.tsx` — file/email scan against `POST /api/analyze` (or `/deep`), rendering verdict, score, reasons, IOCs and the agent's `scan.py`. Sample buttons load `/samples/*.eml`.
- `src/lib/threat-stats.ts` — pure derivations (24h deltas, severity share, daily trend, relative times) with unit tests.
- `public/index.html` (the old single-file UI) has been replaced; `public/report.html` still backs `/v/:id`.

## Live CreateOS micro-VM (at hackathon)
SDK already installed (`@nodeops-createos/sandbox`). In `.env`:
```
MOCK_SANDBOX=false
CREATEOS_SANDBOX_API_KEY=<key from createos.sh>
```
Live path: `createSandbox({egress: []})` → upload target + agent-written
`/tmp/scan.py` → `runCommand(python3)` → parse verdict JSON → `destroy()`.
No key? It fails over to mock and labels the result, so the demo never dies.

## API
- `POST /api/analyze` — multipart `file` (8 MB max) or JSON `{emailText}` → `{verdict, score, reasons, iocs, agent_code, id}`
- `POST /api/analyze/deep` — standard + strict variants in 2 parallel sandboxes → plus `runs[], agreement`
- `GET /api/analyze/history` — recent verdicts (hashes only, no contents)
- `GET /api/analyze/report/:id` — full shareable report · `DELETE` removes it
- `/v/:id` — public report page for sharing
- `GET /api/billing` — plans · `GET /api/billing/checkout` → Stripe · `POST /api/billing/webhook` activates Teams keys (verified signature, or demo admin header without secret)
- `GET /api/health` — `{ok, mock}`. Free tier: 30 scans/hour/IP, bypass with `x-teams-key`.
- `GET /samples/*.eml` — one-click demo emails (clean / phishing / borderline)

## Detection (merged from email-verifier starter)
- 18 brand labels incl. Nigerian banks (GTBank, Kuda, OPAY, Moniepoint…). Set `KNOWN_BANK_DOMAINS` to your banks to cut "unknown domain" noise.
- Lookalike math: homoglyph-normalize (`0→o`, `1→l`, `rn→m`, strip `-`) + Levenshtein ≤ 2 — catches `paypai.com`, `chase-secure.co`.
- Display-name spoof ("says Kuda Bank, came from notice-pay.com"), shown-vs-href mismatch, bare-IP links, BVN/NIN + lottery scam patterns.
- Kept OUR calibration (70/40, not the starter's hotter 20/40) and dropped its live-DNS fallback — DNS needs egress, which contradicts the zero-egress sandbox story.

## Gmail extension (`extension/`)
1. `chrome://extensions` → Developer mode → Load unpacked → `phishshield/extension`
2. Extension options → API URL: local `http://127.0.0.1:3000/api/analyze`, or the public URL after `stripe projects share` (add it to `host_permissions` in manifest.json first)
3. Open any Gmail message → badge appears: ✔ Verified / ⚠ Suspicious / ⛔ Malicious, click for reasons. Uses "Show original" headers when available, else synthesizes `[[LINK text href]]` lines the engine parses.

## Stripe Projects (at venue)
```
npm i -g @stripe/cli
stripe projects init   # hosting + DB for verdict logs
stripe projects add payments   # then paste link into STRIPE_PAYMENT_LINK
stripe projects share  # required for leaderboard
```

## 2-min demo script
1. Clean sample → **Verified** (0, with "SPF/DKIM passed" positive reasons). "Agent wrote scan.py, ran it in a micro-VM with zero egress."
2. Phishing sample → **Malicious** (~200). Point at reasons: lookalike `chase-secure.co`, auth fails, "Link shows chase.com but goes to 192.168.1.99", shortener, BVN/OTP patterns. Open the terminal pane: "this is the exact Python the agent ran."
3. Borderline sample → **deep scan splits**: standard Suspicious (55) vs strict Malicious (69). "Two sandboxes, two analyzer variants, harsher verdict wins."
4. Roadmap slide: Phase 2 — banks sign emails, agent verifies signatures. Pricing: free 30/hr, Teams $19/mo via Stripe.
