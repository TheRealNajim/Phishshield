// Teams key store: keys activated by Stripe checkout webhook (or demo admin activation).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DIR = path.join(__dirname, '..', 'data');
const FILE = path.join(DIR, 'teams.json');

function load() {
  try { return JSON.parse(fs.readFileSync(FILE, 'utf8')); }
  catch { return { keys: [] }; }
}
function save(s) {
  try { fs.mkdirSync(DIR, { recursive: true }); fs.writeFileSync(FILE, JSON.stringify(s, null, 1)); } catch {}
}
function issue(email) {
  const s = load();
  const key = 'tm_' + crypto.randomBytes(12).toString('hex');
  s.keys.push({ key, email: email || null, t: new Date().toISOString() });
  save(s);
  return key;
}
function valid(key) {
  if (!key) return false;
  if (process.env.TEAMS_KEY && key === process.env.TEAMS_KEY) return true; // demo/admin key
  return load().keys.some(k => k.key === key);
}

module.exports = { issue, valid };
