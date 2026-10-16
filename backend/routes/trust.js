'use strict';
// Bank/enterprise "trust" API.
//
// Institutions seal each outbound message (email, SMS, WhatsApp) and append a
// signed verification link before the recipient sees it. Recipients click the
// link to learn whether the message really came from that institution.
//
//   POST   /api/trust/register         [admin]      create an institution + API key
//   GET    /api/trust/institutions     [admin]      list institutions
//   DELETE /api/trust/institutions/:id [admin]      revoke an institution
//   GET    /api/trust/me               [institution] who am I
//   POST   /api/trust/seal             [institution] sign a message, get the link block
//   GET    /api/trust/verify/:token    [public]     verify a token (JSON)
//   POST   /api/trust/verify           [public]     verify a token (JSON body)
//
// The same verify handler powers GET /verify/:token (see server.js) so the link
// a bank appends resolves to the verification result.

const express = require('express');
const institutions = require('../sandbox/institutions');
const tokens = require('../sandbox/trust-tokens');

const router = express.Router();

const CHANNELS = new Set(['email', 'sms', 'whatsapp', 'other']);

function adminKey() {
  return (process.env.ADMIN_KEY || process.env.TEAMS_KEY || '').trim();
}

function requireAdmin(req, res, next) {
  const configured = adminKey();
  if (!configured) return res.status(503).json({ error: 'Admin key not configured (set ADMIN_KEY)' });
  if (String(req.headers['x-admin-key'] || '').trim() !== configured) {
    return res.status(401).json({ error: 'Invalid or missing x-admin-key' });
  }
  next();
}

function apiKeyFrom(req) {
  const header = String(req.headers['x-api-key'] || '').trim();
  if (header) return header;
  const auth = String(req.headers.authorization || '');
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : '';
}

function requireInstitution(req, res, next) {
  const inst = institutions.findByApiKey(apiKeyFrom(req));
  if (!inst) return res.status(401).json({ error: 'Invalid or missing institution API key (x-api-key)' });
  req.institution = inst;
  next();
}

function publicBaseUrl(req) {
  const configured = (process.env.PUBLIC_BASE_URL || '').replace(/\/+$/, '');
  if (configured) return configured;
  return `${req.protocol}://${req.get('host')}`;
}

function isoFromEpoch(seconds) {
  return new Date(seconds * 1000).toISOString();
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function prettyDate(iso) {
  try {
    return new Date(iso).toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' });
  } catch {
    return iso;
  }
}

/** Build the human-readable verification result for any token outcome. */
function verifyResult(token) {
  // The signature check needs the institution's secret, so decode the payload's
  // institution id first, then verify against that institution.
  const dot = String(token || '').lastIndexOf('.');
  let payload = null;
  if (dot > 0) {
    try {
      payload = JSON.parse(Buffer.from(String(token).slice(0, dot), 'base64url').toString('utf8'));
    } catch {
      payload = null;
    }
  }

  const inst = payload && payload.iid ? institutions.get(payload.iid) : null;
  if (!inst || inst.active === false) {
    return {
      valid: false,
      reason: 'unknown_institution',
      message: 'We could not verify this message. The sender is not a registered DeceptIQ institution — treat it with caution and do not share personal details.',
    };
  }

  const checked = tokens.verify(token, inst.secret);
  const institution = institutions.publicView(inst);

  if (!checked.ok) {
    const message =
      checked.reason === 'expired'
        ? `This verification link from ${inst.name} has expired. Ask the sender for a fresh message, or contact them through a number you trust.`
        : 'This verification link is not valid. It may have been altered or forged — do not act on the message it came with.';
    return { valid: false, reason: checked.reason, institution, message };
  }

  const p = checked.payload;
  return {
    valid: true,
    reason: 'verified',
    institution,
    channel: p.ch,
    reference: p.ref,
    issued_at: isoFromEpoch(p.iat),
    expires_at: isoFromEpoch(p.exp),
    message: `This message was signed by ${inst.name} on ${prettyDate(isoFromEpoch(p.iat))}. The link is intact, so the message genuinely came from them.`,
  };
}

// --- Admin: manage institutions -------------------------------------------

router.post('/register', requireAdmin, (req, res) => {
  try {
    const issued = institutions.register({
      name: req.body && req.body.name,
      domains: req.body && req.body.domains,
    });
    res.status(201).json({
      ...issued,
      note: 'Store the api_key and secret now — they are shown once. Use api_key as the x-api-key header to call POST /api/trust/seal.',
    });
  } catch (e) {
    res.status(e.code === 'BAD_REQUEST' ? 400 : 500).json({ error: String(e.message || e) });
  }
});

router.get('/institutions', requireAdmin, (req, res) => {
  res.json({ institutions: institutions.list() });
});

router.delete('/institutions/:id', requireAdmin, (req, res) => {
  if (!institutions.revoke(req.params.id)) return res.status(404).json({ error: 'Institution not found' });
  res.json({ ok: true, id: req.params.id });
});

// --- Institution: seal messages -------------------------------------------

router.get('/me', requireInstitution, (req, res) => {
  res.json({ institution: institutions.publicView(req.institution) });
});

router.post('/seal', requireInstitution, (req, res) => {
  const body = req.body || {};
  const channel = String(body.channel || 'email').toLowerCase();
  if (!CHANNELS.has(channel)) {
    return res.status(400).json({ error: `channel must be one of: ${[...CHANNELS].join(', ')}` });
  }

  const payload = tokens.buildPayload({
    institutionId: req.institution.id,
    channel,
    reference: body.reference,
    subject: body.subject,
    ttlSeconds: Number(body.ttl_seconds),
  });
  const token = tokens.sign(payload, req.institution.secret);
  const verifyUrl = `${publicBaseUrl(req)}/verify/${token}`;
  const name = req.institution.name;

  res.json({
    token,
    verify_url: verifyUrl,
    issued_at: isoFromEpoch(payload.iat),
    expires_at: isoFromEpoch(payload.exp),
    institution: institutions.publicView(req.institution),
    signature: {
      // What the institution appends below every message.
      text: `\uD83D\uDD12 Verify this message came from ${name}: ${verifyUrl}`,
      html:
        `<p style="margin:16px 0 0;font-size:12px;color:#64748b;font-family:sans-serif">` +
        `\uD83D\uDD12 <a href="${escapeHtml(verifyUrl)}" style="color:#0ea5e9">Verify this message came from ${escapeHtml(name)}</a>` +
        `</p>`,
      url: verifyUrl,
    },
  });
});

// --- Public: verify --------------------------------------------------------

function handleVerify(req, res) {
  const token = (req.params && req.params.token) || (req.body && req.body.token) || (req.query && req.query.token);
  if (!token) return res.status(400).json({ error: 'Send a token (path /verify/:token, JSON {token}, or ?token=)' });
  res.json(verifyResult(String(token)));
}

router.get('/verify/:token', handleVerify);
router.post('/verify', handleVerify);

module.exports = { router, handleVerify, verifyResult };
