// Tiny JSONL report store (hackathon-grade persistence; swap for Supabase via Stripe Projects later).
// Each scan is a full shareable report: verdict + reasons + IOCs + agent code. File contents never stored.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DIR = require('./data-dir');
const FILE = path.join(DIR, 'history.jsonl');
const MAX = 200;

function append(entry) {
  const full = { id: crypto.randomBytes(6).toString('hex'), t: new Date().toISOString(), ...entry };
  try {
    fs.mkdirSync(DIR, { recursive: true });
    fs.appendFileSync(FILE, JSON.stringify(full) + '\n');
    const lines = fs.readFileSync(FILE, 'utf8').trim().split('\n');
    if (lines.length > MAX) fs.writeFileSync(FILE, lines.slice(-MAX).join('\n') + '\n');
  } catch {}
  return full;
}

function recent(n = 20) {
  try {
    const lines = fs.readFileSync(FILE, 'utf8').trim().split('\n').filter(Boolean);
    // List view: trim heavy agent_code, keep share id
    return lines.slice(-n).reverse().map(l => {
      const e = JSON.parse(l);
      const { agent_code, ...rest } = e;
      return { ...rest, has_code: !!agent_code };
    });
  } catch { return []; }
}

function get(id) {
  try {
    const lines = fs.readFileSync(FILE, 'utf8').trim().split('\n').filter(Boolean);
    for (let i = lines.length - 1; i >= 0; i--) {
      const e = JSON.parse(lines[i]);
      if (e.id === id) return e;
    }
  } catch {}
  return null;
}

function remove(id) {
  try {
    const lines = fs.readFileSync(FILE, 'utf8').trim().split('\n').filter(Boolean);
    const kept = lines.filter(l => { try { return JSON.parse(l).id !== id; } catch { return true; } });
    fs.writeFileSync(FILE, kept.length ? kept.join('\n') + '\n' : '');
    return kept.length !== lines.length;
  } catch { return false; }
}

module.exports = { append, recent, get, remove };
