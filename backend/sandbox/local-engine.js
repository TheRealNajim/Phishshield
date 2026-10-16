// Node mirror of the Python heuristics in scan-generator.js — for offline dev/tests.
// profile 'strict' (deep-scan variant B): scores scaled 1.25x, thresholds 50/25 instead of 70/40.
function scan(buffer, filename = 'upload.bin', knownDomains = [], opts = {}) {
  const strict = opts.profile === 'strict';
  const known = (knownDomains.length ? knownDomains : (process.env.KNOWN_BANK_DOMAINS || 'chase.com,gtbank.com').split(',')).map(s => s.trim().toLowerCase()).filter(Boolean);
  const crypto = require('crypto');
  const text = buffer.toString('utf8');
  const low = text.toLowerCase();
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
// Brand labels worth imitating (merged: global + Nigerian banks, from email-verifier starter).
const BRANDS = ['paypal', 'google', 'apple', 'microsoft', 'amazon', 'netflix', 'stripe', 'chase', 'bankofamerica',
  'gtbank', 'firstbank', 'accessbank', 'zenithbank', 'opay', 'palmpay', 'kuda', 'moniepoint', 'binance'];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 'tinyurl', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy', 'ow.ly'];
const SCAM_PATTERNS = [
  [/verify your (account|identity|bvn|nin)/i, 'Asks you to verify your account/identity (incl. BVN/NIN)'],
  [/(suspend|deactivat|lock)(ed|ion)? (your )?account/i, 'Threatens to suspend or lock your account'],
  [/(urgent|immediately|within 24 hours|act now|final notice)/i, 'Uses urgency pressure'],
  [/(password|pin|otp|cvv|one[- ]time code)/i, 'Mentions passwords, PINs or OTPs'],
  [/(gift card|wire transfer|crypto(currency)? wallet|send (the )?funds)/i, 'Asks for hard-to-trace payment'],
  [/(you have won|lottery|inheritance|claim your prize)/i, 'Prize or windfall bait'],
];
const rootH = h => String(h || '').toLowerCase().split('.').slice(-2).join('.');
const normLabel = s => String(s || '').toLowerCase().replace(/0/g, 'o').replace(/1/g, 'l').replace(/rn/g, 'm').replace(/-/g, '');
function lev(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++)
    d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
}
// Which brand does this domain imitate, or null? (homoglyph-normalized + Levenshtein)
function imitatedBrand(domain) {
  const label = rootH(domain).split('.')[0];
  if (BRANDS.includes(label)) return null;
  const n = normLabel(label);
  for (const b of BRANDS) {
    if (n === b || (label.length >= 4 && lev(label, b) <= 2) || (n.includes(b) && label !== b)) return b;
  }
  return null;
}
  const urlRe = /https?:\/\/[^\s"'<>]+/gi;
  const urls = text.match(urlRe) || [];
  const doms = [...new Set(urls.map(u => (u.match(/https?:\/\/([^\/:\s]+)/i) || [])[1] || '').filter(Boolean).map(d => d.toLowerCase()))];
  let score = 0; const reasons = [];
  const isEmail = /from:/i.test(text.slice(0, 2000)) && (/authentication-results/i.test(text) || /received:/i.test(text)) || /\.eml$/i.test(filename);

  if (isEmail) {
    // 1. Sender authentication (headers the mail server already stamped)
    const auth = (low.match(/authentication-results:[^\n]+/) || [''])[0];
    const resOf = k => (auth.match(new RegExp(k + '=(\\w+)', 'i')) || [])[1]?.toLowerCase() || null;
    for (const k of ['spf', 'dkim', 'dmarc']) {
      const v = resOf(k);
      if (v === 'pass') reasons.push(`${k.toUpperCase()} passed`);
      else if (v === 'fail') { score += k === 'dmarc' ? 10 : k === 'dkim' ? 25 : 10; reasons.push(`${k.toUpperCase()} failed`); }
      else if (/authentication-results/.test(low)) { score += 5; reasons.push(`${k.toUpperCase()} result missing`); }
    }
    // 2. Sender identity: display name + domain, with homoglyph/Levenshtein lookalike math
    const fm = text.match(/^from:\s*(?:"?([^"<\n]*?)"?\s*)?<([^<>\s\n]+)>|^from:\s*([^\s\n]+)/im);
    const fromName = ((fm && fm[1]) || '').trim();
    const fromAddr = ((fm && (fm[2] || fm[3])) || '').toLowerCase();
    const fromDom = (fromAddr.split('@')[1] || '').trim();
    const senderPuny = fromDom.startsWith('xn--') || fromDom.includes('.xn--');
    if (senderPuny) { score += 30; reasons.push('Sender domain uses punycode (possible fake letters)'); }
    if (fromDom && known.includes(fromDom)) reasons.push(`Sender domain matches known bank domain (${fromDom})`);
    else if (fromDom) {
      const kb = known.find(k => fromDom.includes(k.split('.')[0]));
      const brand = imitatedBrand(fromDom);
      if (kb || /-secure|-verify/.test(fromDom) || fromDom.split('.').length > 3)
        { score += 30; reasons.push(`Lookalike sender domain: ${fromDom}`); }
      else if (brand) { score += 35; reasons.push(`${fromDom} looks like ${brand} but isn't`); }
      else { score += 15; reasons.push(`Sender domain ${fromDom} not in known bank domains`); }
    }
    const claimed = BRANDS.find(b => fromName.toLowerCase().replace(/\s/g, '').includes(b));
    if (claimed && fromDom && !rootH(fromDom).startsWith(claimed))
      { score += 30; reasons.push(`Name says "${fromName}" but it came from ${fromDom}`); }
    // 3. Link destinations: display-text vs href, bare IPs, shorteners, brand-imitating hosts
    const pairs = [...text.matchAll(/<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi)]
      .map(m => ({ href: m[1], text: m[2].replace(/<[^>]+>/g, ' ') }));
    for (const m of text.matchAll(/\[\[LINK text="(.*?)" href="(.*?)"\]\]/g)) pairs.push({ href: m[2], text: m[1] });
    const hostOf = u => { try { return new URL(u).hostname.toLowerCase(); } catch { return ''; } };
    const flagged = new Set();
    for (const p of pairs.slice(0, 50)) {
      const h = hostOf(p.href);
      if (!h || p.href.startsWith('mailto:')) continue;
      const shown = (String(p.text).match(/([a-z0-9-]+\.)+[a-z]{2,}/i) || [])[0]?.toLowerCase();
      if (shown && rootH(shown) !== rootH(h) && !h.endsWith('google.com'))
        { score += 30; flagged.add(h); reasons.push(`Link shows ${shown} but goes to ${h}`); }
      if (/^\d+\.\d+\.\d+\.\d+$/.test(h) && !flagged.has('ip:' + h))
        { score += 25; flagged.add('ip:' + h); reasons.push(`Link goes to a bare IP address (${h})`); }
      const lb = imitatedBrand(h);
      if (lb && !flagged.has('brand:' + h))
        { score += 35; flagged.add('brand:' + h); reasons.push(`Link domain ${h} imitates ${lb}`); }
    }
    for (const hd of new Set(pairs.map(p => hostOf(p.href)).filter(Boolean).concat(doms))) {
      if (!known.includes(hd) && !known.some(k => hd.endsWith('.' + k)) && ![...flagged].some(f => f.endsWith(hd)))
        { score += 25; reasons.push(`Link goes to non-bank domain: ${hd}`); break; }
    }
    if (doms.concat(pairs.map(p => hostOf(p.href))).some(d => SHORTENERS.some(s => d === s || d.includes(s))))
      { score += 15; reasons.push('Shortened URL hides destination'); }
    if (/xn--/.test(text) && !senderPuny) { score += 25; reasons.push('Punycode (IDN homograph) detected'); }
    // 4. Scam language (each pattern once) + urgency×credential combo
    const bodyText = `${text.match(/^subject:[^\n]*/im)?.[0] || ''}\n${text}`;
    for (const [re, why] of SCAM_PATTERNS) if (re.test(bodyText)) { score += 10; reasons.push(why); }
    if (/\b(otp|pin|cvv|password)\b/.test(low) && /urgent|suspend|24\s*hours|immediately|verify now/.test(low))
      { score += 20; reasons.push('Urgent tone + credential (PIN/OTP) request'); }
  } else {
    if (buffer.includes(Buffer.from('/JS')) || buffer.includes(Buffer.from('/JavaScript'))) { score += 25; reasons.push('PDF contains embedded JavaScript (/JS)'); }
    if (['/Launch', '/OpenAction', '/EmbeddedFiles'].some(k => buffer.includes(Buffer.from(k)))) { score += 20; reasons.push('PDF has launch/open-action or embedded files'); }
    if (buffer[0] === 0x50 && buffer[1] === 0x4b && /vbaProject\.bin|AutoOpen|Document_Open/i.test(text)) {
      score += 25; reasons.push('Office doc contains VBA macro markers');
      if (/http|powershell|shell/i.test(text)) { score += 20; reasons.push('Macro-adjacent content references URL/shell'); }
    }
    if (buffer[0] === 0x4d && buffer[1] === 0x5a) {
      reasons.push('Windows executable (static-only, not executed)');
      if (urls.length) { score += 20; reasons.push(`EXE references ${urls.length} URL(s)`); }
      if (/password|credential|powershell/i.test(text)) { score += 25; reasons.push('EXE strings contain credential/shell keywords'); }
    }
    if (urls.length >= 3) { score += 10; reasons.push(`${urls.length} embedded URLs`); }
  }
  if (strict) score = Math.round(score * 1.25);
  const MAL = strict ? 50 : 70, SUS = strict ? 25 : 40;
  const verdict = score >= MAL ? 'Malicious' : score >= SUS ? 'Suspicious' : 'Verified';
  return { verdict, score, reasons: reasons.length ? reasons : ['No red flags found'], iocs: { sha256, urls: urls.slice(0, 20), domains: doms.slice(0, 20) }, kind: isEmail ? 'email' : 'file', size: buffer.length, profile: strict ? 'strict' : 'standard' };
}

module.exports = { scan };
