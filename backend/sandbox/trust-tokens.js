'use strict';
// HMAC-SHA256 verification tokens.
//
// A token is "<base64url(payload)>.<base64url(hmac)>". The payload is a small,
// PII-free JSON object — institution id, channel, an opaque bank-supplied
// reference, issued-at and expiry. Because the whole token ends up in a public
// URL, nothing that identifies the recipient (email, phone, name) may go in it.
//
// Verification recomputes the HMAC with the institution's secret, so a forged
// "verify" link cannot be produced without that secret.

const crypto = require('crypto');

const DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days: email lives in inboxes a while

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

function sign(payload, secret) {
  const body = b64url(JSON.stringify(payload));
  const mac = crypto.createHmac('sha256', String(secret)).update(body).digest('base64url');
  return `${body}.${mac}`;
}

/**
 * Verify a token against a secret.
 * @returns {{ok: true, payload: object} | {ok: false, reason: string}}
 * reasons: malformed | bad_signature | expired
 */
function verify(token, secret) {
  const raw = String(token || '').trim();
  const dot = raw.lastIndexOf('.');
  if (dot <= 0 || dot === raw.length - 1) return { ok: false, reason: 'malformed' };
  const body = raw.slice(0, dot);
  const mac = raw.slice(dot + 1);

  const expected = crypto.createHmac('sha256', String(secret)).update(body).digest('base64url');
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false, reason: 'bad_signature' };

  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  if (!payload || typeof payload !== 'object' || payload.v !== 1 || !payload.iid) {
    return { ok: false, reason: 'malformed' };
  }
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < now) return { ok: false, reason: 'expired' };

  return { ok: true, payload };
}

/** Build the signed payload for a sealed message (no recipient PII). */
function buildPayload({ institutionId, channel, reference, subject, ttlSeconds }) {
  const now = Math.floor(Date.now() / 1000);
  const ttl = Number.isFinite(ttlSeconds) && ttlSeconds > 0 ? Math.floor(ttlSeconds) : DEFAULT_TTL_SECONDS;
  const payload = {
    v: 1,
    iid: institutionId,
    ch: channel,
    ref: reference ? String(reference).slice(0, 120) : null,
    iat: now,
    exp: now + ttl,
  };
  if (subject) payload.sub = String(subject).slice(0, 120);
  return payload;
}

module.exports = { sign, verify, buildPayload, DEFAULT_TTL_SECONDS };
