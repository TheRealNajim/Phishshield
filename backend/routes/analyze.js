const express = require('express');
const multer = require('multer');
const { analyzeBuffer, analyzeDeep } = require('../sandbox/createos-client');
const { buildScanPy } = require('../agent/scan-generator');
const history = require('../sandbox/history');
const teams = require('../sandbox/teams');
const llm = require('../agent/llm');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024 } });

// Natural-language verdicts come from an LLM; refuse early (and cheaply) when
// none is configured rather than running a sandbox and failing afterwards.
function requireLlm(req, res, next) {
  if (!llm.isReady()) {
    return res.status(503).json({
      error: 'Natural-language verdict is unavailable: set LLM_API_KEY (Groq) or GEMINI_API_KEY (see .env.example).',
      code: 'LLM_NOT_CONFIGURED',
    });
  }
  next();
}

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

// Shared multipart/file-or-JSON reader. Returns {buffer, filename} or null after
// already sending a 400.
function readInput(req, res) {
  if (req.file) return { buffer: req.file.buffer, filename: req.file.originalname };
  if (req.body && req.body.emailText) {
    return { buffer: Buffer.from(req.body.emailText, 'utf8'), filename: req.body.filename || 'email.eml' };
  }
  res.status(400).json({ error: 'Send multipart `file` or JSON {emailText}' });
  return null;
}

// Map errors to status codes: LLM misconfiguration/misbehaviour is not a 500.
function fail(res, e) {
  const code = e && e.code;
  if (code === 'LLM_NOT_CONFIGURED') return res.status(503).json({ error: String(e.message || e), code });
  if (code === 'LLM_UPSTREAM' || code === 'LLM_BAD_OUTPUT') return res.status(502).json({ error: String(e.message || e), code });
  return res.status(500).json({ error: String((e && e.message) || e) });
}

// The stored shape of one report. Standard and deep differ only in runs/deep.
function persist(result, filename, deep) {
  return history.append({
    filename,
    verdict: result.verdict,
    score: result.score,
    kind: result.kind,
    reasons: result.reasons,
    iocs: result.iocs,
    size: result.size,
    mode: result.mode,
    agent_code: result.agent_code,
    nl: result.nl,
    ...(deep ? { runs: result.runs, deep: true } : {}),
  });
}

// --- Server-sent events for the live "the agent is working" view ------------

// Note: this watches the RESPONSE's 'close', not the request's. A POST body that
// has been fully read (by multer / express.json) also emits 'close' on the
// request, which would be mistaken for the client hanging up and would silence
// the rest of the stream.
function sseStart(res) {
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no'); // stop a proxy buffering the stream
  if (typeof res.flushHeaders === 'function') res.flushHeaders();
  let done = false;
  res.on('close', () => { done = true; });
  return {
    send(event, data) {
      if (done || res.writableEnded) return;
      try {
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
      } catch {
        done = true;
      }
    },
    close() {
      done = true;
      if (!res.writableEnded) res.end();
    },
  };
}

// The script goes out as fast as the sandbox work allows; the UI reveals it at a
// readable pace itself, so slowing the animation down never slows a scan.
function emitScripts(scripts, send) {
  for (const { profile, code } of scripts) {
    send('script', { profile });
    for (const line of code.split('\n')) send('script_line', { profile, line });
  }
}

async function streamAnalyze(req, res, input, deep) {
  const sse = sseStart(res);
  try {
    const profiles = deep ? ['standard', 'strict'] : ['standard'];

    // 1. The script the agent writes for this job.
    sse.send('status', { step: 'script', label: 'Writing the analyser script', state: 'active' });
    emitScripts(profiles.map((p) => ({ profile: p, code: buildScanPy(input.filename, p) })), sse.send);
    sse.send('status', { step: 'script', label: 'Writing the analyser script', state: 'done', detail: profiles.join(' + ') });

    // 2. Run it (live micro-VM, or the local engine in mock mode).
    const runLabel = deep ? 'Running two analyser variants' : 'Running the analyser';
    sse.send('status', { step: 'run', label: runLabel, state: 'active' });
    const result = deep
      ? await analyzeDeep(input.buffer, input.filename, { knownDomains: knownDomains() })
      : await analyzeBuffer(input.buffer, input.filename, { knownDomains: knownDomains() });
    sse.send('status', { step: 'run', label: runLabel, state: 'done', detail: `${result.verdict} · risk ${result.score}` });

    // 3. The plain-English verdict. This is the slow step, so stream each
    //    provider/model attempt — a provider reporting "high demand" becomes
    //    visible retry traffic instead of a mystery pause.
    sse.send('status', { step: 'verdict', label: 'Writing the plain-English verdict', state: 'active' });
    result.nl = await llm.explain(
      { ...result, filename: input.filename },
      { onAttempt: (e) => sse.send('llm', e) },
    );
    sse.send('status', { step: 'verdict', label: 'Writing the plain-English verdict', state: 'done', detail: result.nl.model });

    const saved = persist(result, input.filename, deep);
    sse.send('result', { ...result, id: saved.id });
  } catch (e) {
    sse.send('error', { error: String((e && e.message) || e), code: (e && e.code) || 'ERROR' });
  } finally {
    sse.close();
  }
}

// POST /api/analyze  (multipart: file) OR (json: {emailText, filename})
router.post('/', requireLlm, rateLimited, upload.single('file'), async (req, res) => {
  const input = readInput(req, res);
  if (!input) return;
  try {
    const result = await analyzeBuffer(input.buffer, input.filename, { knownDomains: knownDomains() });
    result.nl = await llm.explain({ ...result, filename: input.filename });
    const saved = persist(result, input.filename, false);
    res.json({ ...result, id: saved.id });
  } catch (e) {
    fail(res, e);
  }
});

// POST /api/analyze/deep — two analyzer variants in two parallel sandboxes, compared
router.post('/deep', requireLlm, rateLimited, upload.single('file'), async (req, res) => {
  const input = readInput(req, res);
  if (!input) return;
  try {
    const result = await analyzeDeep(input.buffer, input.filename, { knownDomains: knownDomains() });
    result.nl = await llm.explain({ ...result, filename: input.filename });
    const saved = persist(result, input.filename, true);
    res.json({ ...result, id: saved.id });
  } catch (e) {
    fail(res, e);
  }
});

// POST /api/analyze/stream — same input as POST /, but streams the agent's
// script and phase updates as server-sent events, then the finished report.
router.post('/stream', requireLlm, rateLimited, upload.single('file'), (req, res) => {
  const input = readInput(req, res);
  if (!input) return;
  return streamAnalyze(req, res, input, false);
});

// POST /api/analyze/deep/stream — the deep scan, streamed.
router.post('/deep/stream', requireLlm, rateLimited, upload.single('file'), (req, res) => {
  const input = readInput(req, res);
  if (!input) return;
  return streamAnalyze(req, res, input, true);
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
