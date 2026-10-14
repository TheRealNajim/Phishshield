const express = require('express');
const multer = require('multer');
const { analyzeBuffer, analyzeDeep } = require('../sandbox/createos-client');
const history = require('../sandbox/history');
const teams = require('../sandbox/teams');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024 } });

// Free-tier rate limit: 30 scans/hour/IP. Teams bypass via x-teams-key (demo stub for Stripe paywall).
const hits = new Map();
const FREE_PER_HOUR = 30;
function rateLimited(req, res, next) {
  if (teams.valid(req.headers['x-teams-key'])) return next(); // Teams: unlimited
  const ip = req.ip || 'local';
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter(t => now - t < 3600e3);
  if (arr.length >= FREE_PER_HOUR) return res.status(429).json({ error: 'Free tier: 30 scans/hour. Upgrade to Teams for unlimited.', upgrade: '/api/billing' });
  arr.push(now); hits.set(ip, arr);
  next();
}

function knownDomains() {
  return (process.env.KNOWN_BANK_DOMAINS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
}

// POST /api/analyze  (multipart: file) OR (json: {emailText, filename})
router.post('/', rateLimited, upload.single('file'), async (req, res) => {
  try {
    let buffer, filename;
    if (req.file) { buffer = req.file.buffer; filename = req.file.originalname; }
    else if (req.body.emailText) { buffer = Buffer.from(req.body.emailText, 'utf8'); filename = req.body.filename || 'email.eml'; }
    else return res.status(400).json({ error: 'Send multipart `file` or JSON {emailText}' });

    const result = await analyzeBuffer(buffer, filename, { knownDomains: knownDomains() });
    const saved = history.append({ filename, verdict: result.verdict, score: result.score, kind: result.kind, reasons: result.reasons, iocs: result.iocs, size: result.size, mode: result.mode, agent_code: result.agent_code });
    res.json({ ...result, id: saved.id });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// POST /api/analyze/deep — two analyzer variants in two parallel sandboxes, compared
router.post('/deep', rateLimited, upload.single('file'), async (req, res) => {
  try {
    let buffer, filename;
    if (req.file) { buffer = req.file.buffer; filename = req.file.originalname; }
    else if (req.body.emailText) { buffer = Buffer.from(req.body.emailText, 'utf8'); filename = req.body.filename || 'email.eml'; }
    else return res.status(400).json({ error: 'Send multipart `file` or JSON {emailText}' });

    const result = await analyzeDeep(buffer, filename, { knownDomains: knownDomains() });
    const saved = history.append({ filename, verdict: result.verdict, score: result.score, kind: result.kind, reasons: result.reasons, iocs: result.iocs, size: result.size, mode: result.mode, runs: result.runs, agent_code: result.agent_code, deep: true });
    res.json({ ...result, id: saved.id });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// GET /api/analyze/history — recent verdicts (no file contents, hashes only)
router.get('/history', (req, res) => res.json(history.recent(20)));

// GET /api/analyze/report/:id — full shareable report
router.get('/report/:id', (req, res) => {
  const r = history.get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Report not found (reports live on this server only)' });
  res.json(r);
});

// DELETE /api/analyze/report/:id — delete your report (privacy: hashes + code only, but yours to remove)
router.delete('/report/:id', (req, res) => {
  if (!history.remove(req.params.id)) return res.status(404).json({ error: 'Report not found' });
  res.json({ ok: true });
});

module.exports = router;
