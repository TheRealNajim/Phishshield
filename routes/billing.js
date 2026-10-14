const express = require('express');
const crypto = require('crypto');
const teams = require('../sandbox/teams');

const router = express.Router();

// Plans + checkout. Free = 30 scans/hour/IP, Teams = unlimited via x-teams-key.
// At the hackathon: create a $19/mo Payment Link in the Stripe dashboard
// (or `stripe projects add payments`) and set STRIPE_PAYMENT_LINK.
router.get('/', (req, res) => res.json({
  free: { name: 'Personal', price: 0, limit: '30 scans/hour' },
  teams: {
    name: 'Teams',
    price: '$19/mo',
    perks: ['unlimited scans', 'staff inbox API', 'audit log'],
    checkout: process.env.STRIPE_PAYMENT_LINK || null,
    hint: !process.env.STRIPE_PAYMENT_LINK ? 'Set STRIPE_PAYMENT_LINK env to a Stripe Payment Link to go live' : undefined,
  },
}));

// GET /api/billing/checkout — send the buyer to Stripe; webhook activates their key
router.get('/checkout', (req, res) => {
  if (!process.env.STRIPE_PAYMENT_LINK) return res.status(501).json({ error: 'No STRIPE_PAYMENT_LINK set (see README)' });
  res.redirect(process.env.STRIPE_PAYMENT_LINK);
});

// Verify a Stripe webhook signature by hand (no SDK needed):
// header "t=...,v1=...,v1=...", HMAC_SHA256(secret, `${t}.${rawBody}`)
function stripeSigOk(raw, header, secret, tolSec = 300) {
  if (!header || !secret) return false;
  const parts = {};
  for (const kv of String(header).split(',')) {
    const i = kv.indexOf('=');
    if (i > 0) (parts[kv.slice(0, i)] ||= []).push(kv.slice(i + 1));
  }
  const t = Number((parts.t || [])[0]);
  if (!t || Math.abs(Date.now() / 1000 - t) > tolSec) return false;
  const want = crypto.createHmac('sha256', secret).update(`${t}.${raw}`).digest('hex');
  return (parts.v1 || []).some(v => {
    try { return crypto.timingSafeEqual(Buffer.from(v), Buffer.from(want)); } catch { return false; }
  });
}

// POST /api/billing/webhook — Stripe sends checkout.session.completed here.
// Mounted on express.raw in server.js so req.body is the raw Buffer.
router.post('/webhook', (req, res) => {
  const raw = req.body instanceof Buffer ? req.body.toString('utf8') : JSON.stringify(req.body || {});
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  let evt;
  try { evt = JSON.parse(raw); } catch { return res.status(400).json({ error: 'bad JSON' }); }

  if (secret) {
    if (!stripeSigOk(raw, req.headers['stripe-signature'], secret)) return res.status(401).json({ error: 'bad signature' });
  } else {
    // Demo mode (no secret configured): only the admin demo key may fire fake events.
    if (req.headers['x-teams-key'] !== process.env.TEAMS_KEY) return res.status(401).json({ error: 'demo mode: send x-teams-key admin header' });
  }

  if (evt.type === 'checkout.session.completed') {
    const email = (evt.data && evt.data.object && (evt.data.object.customer_email || evt.data.object.customer_details?.email)) || null;
    const key = teams.issue(email);
    return res.json({ ok: true, teams_key: key, note: 'Send as x-teams-key header for unlimited scans' });
  }
  res.json({ ok: true, ignored: evt.type || 'unknown' });
});

module.exports = router;
