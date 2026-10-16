require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const analyzeRoute = require('./routes/analyze');
const billingRoute = require('./routes/billing');
const trustRoute = require('./routes/trust');
const llm = require('./agent/llm');

const app = express();
app.set('trust proxy', 1);
app.use(cors());
// Stripe webhook needs the RAW body for signature verification — mount before express.json
app.use('/api/billing/webhook', express.raw({ type: 'application/json', limit: '1mb' }));
app.use(express.json({ limit: '2mb' }));

// Sample .eml files + the public report page live in public/
app.use(express.static(path.join(__dirname, 'public')));

// The dashboard is a Vite + React app in ../frontend/ — build it with `npm run build`.
const FRONTEND_DIST = path.join(__dirname, '..', 'frontend', 'dist');
const FRONTEND_INDEX = path.join(FRONTEND_DIST, 'index.html');
app.use(express.static(FRONTEND_DIST));

app.get('/api/health', (req, res) => res.json({ ok: true, mock: process.env.MOCK_SANDBOX !== 'false', llm: llm.isConfigured() }));
app.use('/api/analyze', analyzeRoute);
app.use('/api/billing', billingRoute);
app.use('/api/trust', trustRoute.router);
// The verification link an institution appends resolves here (JSON for now; a
// branded page lands in the UI phase).
app.get('/verify/:token', trustRoute.handleVerify);
// Shareable verdict pages (report.html fetches /api/analyze/report/:id)
app.get('/v/:id', (req, res) => res.sendFile(path.join(__dirname, 'public', 'report.html')));

// SPA fallback: any non-API GET renders the dashboard shell (client-side routing).
app.get(/^\/(?!api\/).*/, (req, res) => {
  if (!fs.existsSync(FRONTEND_INDEX)) {
    return res
      .status(503)
      .type('text/plain')
      .send('Frontend build not found. Run `npm run build` (repo root) or `npm --prefix frontend run build`.');
  }
  res.sendFile(FRONTEND_INDEX);
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    const built = fs.existsSync(FRONTEND_INDEX);
    console.log(`PhishShield on http://localhost:${PORT} (MOCK=${process.env.MOCK_SANDBOX !== 'false'}, frontend=${built ? 'built' : 'MISSING — run npm run build'})`);
  });
}
module.exports = app;
