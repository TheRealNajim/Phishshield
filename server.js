require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const analyzeRoute = require('./routes/analyze');
const billingRoute = require('./routes/billing');

const app = express();
app.set('trust proxy', 1);
app.use(cors());
// Stripe webhook needs the RAW body for signature verification — mount before express.json
app.use('/api/billing/webhook', express.raw({ type: 'application/json', limit: '1mb' }));
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/health', (req, res) => res.json({ ok: true, mock: process.env.MOCK_SANDBOX !== 'false' }));
app.use('/api/analyze', analyzeRoute);
app.use('/api/billing', billingRoute);
// Shareable verdict pages (report.html fetches /api/analyze/report/:id)
app.get('/v/:id', (req, res) => res.sendFile(path.join(__dirname, 'public', 'report.html')));

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`PhishShield on http://localhost:${PORT} (MOCK=${process.env.MOCK_SANDBOX !== 'false'})`));
}
module.exports = app;
