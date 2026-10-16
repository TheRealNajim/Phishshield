'use strict';
// Institution registry: banks and other senders that sign their messages with
// DeceptIQ so recipients can verify authenticity.
//
// Storage is a small JSON file (hackathon-grade; swap for a DB later). Each
// institution gets an API key (auth for /api/trust/seal) and a signing secret
// (HMAC key for verification tokens). The secret never leaves the server and is
// never returned after registration.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const FILE = path.join(__dirname, '..', 'data', 'institutions.json');

function load() {
  try {
    const parsed = JSON.parse(fs.readFileSync(FILE, 'utf8'));
    if (parsed && Array.isArray(parsed.institutions)) return parsed;
  } catch {
    /* first run or corrupt file -> empty registry */
  }
  return { institutions: [] };
}

function save(state) {
  fs.mkdirSync(path.dirname(FILE), { recursive: true });
  fs.writeFileSync(FILE, JSON.stringify(state, null, 1));
}

function hashKey(key) {
  return crypto.createHash('sha256').update(String(key)).digest('hex');
}

function safeEqualHex(a, b) {
  const ba = Buffer.from(String(a || ''), 'hex');
  const bb = Buffer.from(String(b || ''), 'hex');
  if (ba.length === 0 || ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function normalizeDomains(domains) {
  if (!Array.isArray(domains)) return [];
  return [...new Set(
    domains
      .map((d) => String(d).trim().toLowerCase())
      .filter(Boolean),
  )];
}

/** Public view: everything except the API-key hash and the signing secret. */
function publicView(inst) {
  if (!inst) return null;
  return {
    id: inst.id,
    name: inst.name,
    domains: inst.domains || [],
    created_at: inst.created_at,
    active: inst.active !== false,
  };
}

/**
 * Register an institution and issue credentials.
 * @returns {{institution: object, api_key: string, secret: string}} api_key + secret are shown once.
 */
function register({ name, domains } = {}) {
  const cleanName = String(name || '').trim();
  if (!cleanName) {
    const e = new Error('Institution name is required');
    e.code = 'BAD_REQUEST';
    throw e;
  }
  const state = load();
  const inst = {
    id: 'inst_' + crypto.randomBytes(6).toString('hex'),
    name: cleanName,
    domains: normalizeDomains(domains),
    api_key_hash: hashKey('pending'),
    secret: crypto.randomBytes(32).toString('hex'),
    created_at: new Date().toISOString(),
    active: true,
  };
  const apiKey = 'dpiq_' + crypto.randomBytes(20).toString('hex');
  inst.api_key_hash = hashKey(apiKey);
  state.institutions.push(inst);
  save(state);
  return { institution: publicView(inst), api_key: apiKey, secret: inst.secret };
}

/** Look up an active institution by its API key. */
function findByApiKey(apiKey) {
  const key = String(apiKey || '').trim();
  if (!key) return null;
  const wanted = hashKey(key);
  return load().institutions.find((i) => i.active !== false && safeEqualHex(i.api_key_hash, wanted)) || null;
}

function get(id) {
  return load().institutions.find((i) => i.id === id) || null;
}

function list() {
  return load().institutions.map(publicView);
}

function revoke(id) {
  const state = load();
  const inst = state.institutions.find((i) => i.id === id);
  if (!inst) return false;
  inst.active = false;
  save(state);
  return true;
}

module.exports = { register, findByApiKey, get, list, revoke, publicView, hashKey };
