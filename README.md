# PhishShield — hackathon MVP

Agent that writes + runs its own Python in a CreateOS sandbox to verdict sketchy files/emails.
Free for individuals, Teams ($19/mo) for staff inbox protection.

## Layout
- `backend/` — Express API + scan engine/agent, the Gemini natural-language verdict, the trust API, tests and sample files
- `frontend/` — Vite + React dashboard (built into `frontend/dist`, served by the backend)
- `extension/` — Chrome extension

## Run locally (mock sandbox)
```
cd backend
npm install
npm --prefix ../frontend install
cp .env.example .env            # PowerShell: Copy-Item .env.example .env
# 1) get a free Gemini key: https://aistudio.google.com/apikey
# 2) paste it into backend/.env as GEMINI_API_KEY=...
npm run llm:check               # confirms the natural-language verdict works
npm run build                   # builds ../frontend/dist (Express serves it)
npm test                        # 34 checks: engine + analyze/deep/report/share/billing API + py parity + trust API
npm start
# open http://127.0.0.1:3000
```
Scan verdicts now hard-require `GEMINI_API_KEY` (503 without it). CreateOS and
Stripe are optional — see below.

## Frontend (`frontend/`)
The dashboard is a Vite + React 19 + TypeScript + Tailwind 4 app (shadcn/radix components included).
`backend/server.js` serves `../frontend/dist` at `/` with an SPA fallback, so the API and UI share one origin.

```
cd backend
npm run build                        # build the dashboard (also: npm --prefix ../frontend run build)
npm --prefix ../frontend run dev     # Vite dev server with HMR; proxies /api to Express on :3000
npm --prefix ../frontend test        # vitest: stats helpers, render + scan-flow tests
npm --prefix ../frontend run typecheck
```
- `src/pages/Dashboard.tsx` — the dashboard: stats, severity split, 7-day trend and recent verdicts come from `GET /api/analyze/history`; sandbox mode from `/api/health`; the upgrade card from `/api/billing`.
- `src/components/scan-panel.tsx` — file/email scan against `POST /api/analyze` (or `/deep`), rendering verdict, score, reasons, IOCs and the agent's `scan.py`. Sample buttons load `/samples/*.eml`.
- `src/lib/threat-stats.ts` — pure derivations (24h deltas, severity share, daily trend, relative times) with unit tests.
- `backend/public/report.html` backs the public `/v/:id` report page.

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
- `POST /api/analyze` — multipart `file` (8 MB max) or JSON `{emailText}` → `{verdict, score, reasons, iocs, agent_code, nl, id}`
- `POST /api/analyze/deep` — standard + strict variants in 2 parallel sandboxes → plus `runs[], agreement`
- `GET /api/analyze/history` — recent verdicts (hashes only, no contents)
- `GET /api/analyze/report/:id` — full shareable report · `DELETE` removes it
- `/v/:id` — public report page for sharing
- `GET /api/billing` — plans · `GET /api/billing/checkout` → Stripe · `POST /api/billing/webhook` activates Teams keys (verified signature, or demo admin header without secret)
- `GET /api/health` — `{ok, mock, llm}`. Free tier: 30 scans/hour/IP, bypass with `x-teams-key`.
- `GET /samples/*.eml` — one-click demo emails (clean / phishing / borderline)

## Natural-language verdict (Gemini)
The deterministic engine still decides the verdict, score and evidence. A Gemini
call then turns that evidence into a plain-English verdict, returned as `nl`:

```json
{ "headline": "This email is a phishing attempt impersonating Chase.",
  "summary": "…why, in 2-4 sentences…",
  "action": "…what the reader should do…",
  "confidence": "high", "verdict": "Malicious", "risk_score": 210,
  "provider": "gemini", "model": "gemini-3-flash-preview", "generated_at": "…" }
```
- Requires `GEMINI_API_KEY`. Without it `POST /api/analyze[/deep]` returns **503** (`code: LLM_NOT_CONFIGURED`); an upstream/parse failure returns **502**. `GET /api/health` reports `llm: true|false`.
- Only derived signals (verdict, score, reasons, IOCs, deep runs) are sent — never the raw file/message — and the evidence is treated as untrusted data, not instructions.
- Overrides: `GEMINI_MODEL` (primary), `GEMINI_FALLBACK_MODELS` (comma-separated), `GEMINI_BASE_URL`, `GEMINI_TIMEOUT_MS` (per model), `GEMINI_TOTAL_BUDGET_MS` (whole chain).
- **Model fallback:** Google retires models (`404`), overloads them (`503`) and throttles free-tier quota (`429`). The client tries `GEMINI_MODEL` first, then a fallback chain, and uses the first model that answers. A slow or overloaded model never aborts the chain — it moves on to the next until the overall budget runs out. Run `npm run llm:check` to see the chain and test your key.

## Trust API (`backend/routes/trust.js`) — institutions sign their messages
Banks seal every outbound email/SMS and append a signed verification link below it
(like a signature). Recipients click through to learn whether it really came from them.

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `POST /api/trust/register` | `x-admin-key` | create an institution, issue `api_key` + `secret` (shown once) |
| `GET /api/trust/institutions` | `x-admin-key` | list institutions |
| `DELETE /api/trust/institutions/:id` | `x-admin-key` | revoke |
| `GET /api/trust/me` | `x-api-key` | the calling institution |
| `POST /api/trust/seal` | `x-api-key` | sign a message → `{token, verify_url, expires_at, signature:{text,html,url}}` |
| `GET /api/trust/verify/:token` · `POST /api/trust/verify` | public | `{valid, reason, institution, message, …}` |
| `GET /verify/:token` | public | the link banks append below messages (JSON for now; branded page comes with the UI phase) |

```bash
# register a bank (admin)
curl -s localhost:3000/api/trust/register -H 'x-admin-key: demo-admin-key' \
  -H 'content-type: application/json' -d '{"name":"GTBank","domains":["gtbank.com"]}'

# seal a message and get the block to append (institution)
curl -s localhost:3000/api/trust/seal -H 'x-api-key: dpiq_…' \
  -H 'content-type: application/json' -d '{"channel":"email","reference":"stmt-05"}'

# what a recipient sees when they click the link
curl -s localhost:3000/verify/<token>
```
Token = `base64url(payload) + "." + HMAC-SHA256(payload, secret)`. The payload holds
only `{v, iid, ch, ref, sub, iat, exp}` — **no recipient PII**, since the token rides in a
public URL. Tampering, an unknown/revoked issuer, or expiry all fail verification.
Set `ADMIN_KEY` (falls back to `TEAMS_KEY`) and `PUBLIC_BASE_URL` in `.env`.


## Detection (merged from email-verifier starter)
- 18 brand labels incl. Nigerian banks (GTBank, Kuda, OPAY, Moniepoint…). Set `KNOWN_BANK_DOMAINS` to your banks to cut "unknown domain" noise.
- Lookalike math: homoglyph-normalize (`0→o`, `1→l`, `rn→m`, strip `-`) + Levenshtein ≤ 2 — catches `paypai.com`, `chase-secure.co`.
- Display-name spoof ("says Kuda Bank, came from notice-pay.com"), shown-vs-href mismatch, bare-IP links, BVN/NIN + lottery scam patterns.
- Kept OUR calibration (70/40, not the starter's hotter 20/40) and dropped its live-DNS fallback — DNS needs egress, which contradicts the zero-egress sandbox story.

## Gmail extension (`extension/`)
1. `chrome://extensions` → Developer mode → Load unpacked → `extension/`
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
