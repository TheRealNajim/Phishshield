// Point every JSON store at a throwaway directory *before* anything reads it, so
// test scans never land in the real reports the dashboard serves.
const fs = require('fs');
const os = require('os');
const path = require('path');
process.env.PHISHSHIELD_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'phishshield-data-'));

const { scan } = require('../sandbox/local-engine');

const cases = [
  { name: 'clean bank email -> Verified', buf: Buffer.from('From: alerts@chase.com\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\nSubject: statement\n\nSee https://chase.com/statements'), file: 'a.eml', want: 'Verified' },
  { name: 'lookalike + dkim fail + IP link + OTP -> Malicious', buf: Buffer.from('From: alerts@chase-secure.co\nAuthentication-Results: spf=fail dkim=fail dmarc=fail\nSubject: URGENT verify\n\nsuspended in 24 hours give PIN and OTP <a href="http://192.168.1.99/login">https://chase.com/login</a> http://bit.ly/x9z'), file: 'b.eml', want: 'Malicious' },
  { name: 'pdf with JS -> Suspicious+', buf: Buffer.from('%PDF-1.4 /JS (http://evil.example/x) /OpenAction'), file: 'evil.pdf', wantScore: 40 },
  { name: 'clean txt -> Verified', buf: Buffer.from('Hello team, meeting notes attached. Nothing to see here.'), file: 'notes.txt', want: 'Verified' },
  { name: 'exe MZ + url + powershell -> Suspicious', buf: Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.from('.... http://evil.example/payload powershell -enc credential dump')]), file: 'setup.exe', want: 'Suspicious' },
  { name: 'punycode link email -> Suspicious+', buf: Buffer.from('From: alerts@chase.com\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\nSubject: hello\n\nclick https://xn--chse-9na.com/login urgently verify now with your password'), file: 'c.eml', wantScore: 30 },
  { name: 'homoglyph sender (paypai ~ paypal) -> Suspicious', buf: Buffer.from('From: support@paypai.com\nSubject: receipt\n\nThanks https://paypai.com/r'), file: 'd.eml', want: 'Suspicious' },
  { name: 'display-name spoof (Kuda name, strange domain) -> Suspicious', buf: Buffer.from('From: Kuda Bank <support@notice-pay.com>\nSubject: hello\n\nHi there'), file: 'e.eml', want: 'Suspicious' },
  { name: 'BVN lure on lookalike accessbank host -> Malicious', buf: Buffer.from('From: alerts@accessbankplc.com\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\nSubject: x\n\nKindly verify your BVN now at https://accessbankplc.com.evil.ng/login'), file: 'f.eml', want: 'Malicious' },
  { name: 'extension LINK lines catch display-vs-href mismatch', buf: Buffer.from('From: Kuda Bank <alerts@kuda.com>\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\nSubject: x\n\nTap to continue\n[[LINK text="https://kuda.com/login" href="http://45.9.20.11/login"]]'), file: 'g.eml', wantScore: 50, wantReason: 'Link shows' },
];

function check(label, ok) {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label}`);
  return ok ? 0 : 1;
}

async function main() {
  let fail = 0;

  // --- Engine parity (no LLM involved) --------------------------------------
  for (const c of cases) {
    const r = scan(c.buf, c.file, ['chase.com']);
    let ok = c.want ? r.verdict === c.want : r.score >= c.wantScore;
    if (ok && c.wantReason) ok = r.reasons.some(x => x.includes(c.wantReason));
    console.log(`${ok ? 'PASS' : 'FAIL'} ${c.name} => ${r.verdict} (${r.score}) :: ${r.reasons.join('; ')}`);
    if (!ok) fail++;
  }

  // --- API integration (mock sandbox) ---------------------------------------
  process.env.MOCK_SANDBOX = 'true';
  const app = require('../server');
  const srv = app.listen(0);
  await new Promise(r => srv.on('listening', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    // Without any LLM provider key the analyze endpoints must refuse (hard fail).
    // Clear every provider, not just Gemini, so a key in .env can't mask this.
    delete process.env.GEMINI_API_KEY;
    delete process.env.LLM_API_KEY;
    delete process.env.GROQ_API_KEY;
    let res = await fetch(base + '/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ emailText: 'From: a@chase.com\nReceived: x\n\nhi' }) });
    let j = await res.json();
    fail += check(`POST /api/analyze without LLM key => 503 (${res.status}, ${j.code || 'no code'})`, res.status === 503 && j.code === 'LLM_NOT_CONFIGURED');

    // With a key but an unreachable provider, the failure must read as an upstream fault (502), not a 500.
    process.env.LLM_PROVIDER = 'gemini';
    process.env.GEMINI_API_KEY = 'test-key';
    process.env.GEMINI_BASE_URL = 'http://127.0.0.1:1';
    res = await fetch(base + '/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ emailText: 'From: a@chase.com\nReceived: x\n\nhi' }) });
    j = await res.json();
    fail += check(`POST /api/analyze with unreachable Gemini => 502 (${res.status}, ${j.code || 'no code'})`, res.status === 502 && j.code === 'LLM_UPSTREAM');
    delete process.env.GEMINI_BASE_URL;

    // The OpenAI-compatible provider (Groq shape) must honour the same contract.
    delete process.env.GEMINI_API_KEY;
    process.env.LLM_PROVIDER = 'openai';
    process.env.LLM_API_KEY = 'test-key';
    process.env.LLM_BASE_URL = 'http://127.0.0.1:1';
    res = await fetch(base + '/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ emailText: 'From: a@chase.com\nReceived: x\n\nhi' }) });
    j = await res.json();
    fail += check(`POST /api/analyze with unreachable OpenAI-compatible LLM => 502 (${res.status}, ${j.code || 'no code'})`, res.status === 502 && j.code === 'LLM_UPSTREAM');
    delete process.env.LLM_BASE_URL;
    delete process.env.LLM_API_KEY;
    delete process.env.LLM_PROVIDER;
    process.env.GEMINI_API_KEY = 'test-key'; // keep one provider configured so /api/health reports llm:true

    // Install the natural-language provider (no network in tests).
    const llm = require('../agent/llm');
    llm.setProvider(async (s) => ({
      headline: `${s.verdict} verdict for ${s.filename || 'input'}`,
      summary: `Risk score ${s.score}. Evidence: ${(s.reasons || []).join('; ') || 'none'}.`,
      action: 'Confirm with your bank through a number you trust before acting.',
      confidence: 'high',
      verdict: s.verdict,
      risk_score: s.score,
      provider: 'test',
      model: 'test-model',
      generated_at: new Date().toISOString(),
    }));

    res = await fetch(base + '/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ emailText: 'From: alerts@chase.com\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\n\nSee https://chase.com/x' }) });
    j = await res.json();
    const ok1 = j.verdict === 'Verified' && typeof j.agent_code === 'string' && j.nl && j.nl.headline && j.nl.summary && j.nl.action;
    console.log(`${ok1 ? 'PASS' : 'FAIL'} POST /api/analyze email => ${j.verdict} (nl: ${j.nl ? `"${j.nl.headline}"` : 'MISSING'})`); if (!ok1) fail++;

    res = await fetch(base + '/api/analyze/history');
    j = await res.json();
    const ok2 = Array.isArray(j) && j.length >= 1;
    console.log(`${ok2 ? 'PASS' : 'FAIL'} GET /api/analyze/history => ${Array.isArray(j) ? j.length : typeof j} entries`); if (!ok2) fail++;

    res = await fetch(base + '/api/health');
    j = await res.json();
    const okH = j.ok === true && j.llm === true;
    console.log(`${okH ? 'PASS' : 'FAIL'} GET /api/health => llm=${j.llm}`); if (!okH) fail++;

    res = await fetch(base + '/api/billing');
    j = await res.json();
    const ok3 = j.free && j.teams;
    console.log(`${ok3 ? 'PASS' : 'FAIL'} GET /api/billing => free+teams plans`); if (!ok3) fail++;

    // Deep scan: borderline input should split the two runs (standard Verified, strict Suspicious+)
    res = await fetch(base + '/api/analyze/deep', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ emailText: 'From: alerts@chase.com\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\nSubject: hello\n\nclick https://xn--chse-9na.com/login urgently verify now with your password' }) });
    j = await res.json();
    const ok4 = Array.isArray(j.runs) && j.runs.length === 2 && typeof j.agreement === 'boolean' && j.id && j.nl && j.nl.summary;
    console.log(`${ok4 ? 'PASS' : 'FAIL'} POST /api/analyze/deep => ${j.runs ? j.runs.map(r => r.profile + ':' + r.verdict + '(' + r.score + ')').join(' vs ') : 'no runs'} agree=${j.agreement} nl=${j.nl ? 'yes' : 'no'}`); if (!ok4) fail++;

    // Streamed scan: the agent's script and phase updates arrive as SSE, then the report.
    res = await fetch(base + '/api/analyze/stream', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ emailText: 'From: alerts@chase.com\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\n\nSee https://chase.com/x' }) });
    const sse = await res.text();
    // Match "event: name\n" so "script" cannot also match "script_line".
    const count = (name) => (sse.match(new RegExp(`event: ${name}\n`, 'g')) || []).length;
    const dataOf = (block) => { const l = block.split('\n').find(x => x.startsWith('data: ')); return l ? JSON.parse(l.slice(6)) : null; };
    const lines = sse.split('\n\n').filter(b => b.startsWith('event: script_line')).map(b => dataOf(b).line);
    const resultBlock = sse.split('\n\n').find(b => b.startsWith('event: result'));
    const streamed = dataOf(resultBlock || '');
    // The script embeds a timestamp at build time, so compare with it normalised out.
    const strip = (s) => String(s).replace(/# Agent-written by PhishShield @[^\n]*/, '# Agent-written by PhishShield @<t>');
    const okS = res.status === 200
      && (res.headers.get('content-type') || '').includes('text/event-stream')
      && count('status') >= 3 && count('script') === 1 && count('script_line') > 20
      && streamed && typeof streamed.id === 'string'
      && strip(lines.join('\n')) === strip(streamed.agent_code);
    console.log(`${okS ? 'PASS' : 'FAIL'} POST /api/analyze/stream => ${lines.length} script lines, ${count('status')} status events, result=${!!streamed}${streamed ? ' id=' + streamed.id : ''}`); if (!okS) fail++;

    // Shareable report round-trip
    res = await fetch(base + '/api/analyze/report/' + j.id);
    let rep = await res.json();
    const ok5 = rep.id === j.id && rep.verdict === j.verdict && rep.nl && rep.nl.summary;
    console.log(`${ok5 ? 'PASS' : 'FAIL'} GET /api/analyze/report/:id => ${rep.verdict} (${rep.score}) nl=${rep.nl ? 'stored' : 'missing'}`); if (!ok5) fail++;

    res = await fetch(base + '/v/' + j.id);
    const html = await res.text();
    const ok6 = res.status === 200 && html.includes('shared report');
    console.log(`${ok6 ? 'PASS' : 'FAIL'} GET /v/:id => share page ${res.status}`); if (!ok6) fail++;

    // Generated Python parity: the agent's strict scan.py must run and agree with Node
    const { buildScanPy } = require('../agent/scan-generator');
    const fs = require('fs'), os = require('os'), path = require('path'), cp = require('child_process');
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'phish-'));
    fs.writeFileSync(path.join(tmp, 'scan.py'), buildScanPy('email.eml', 'strict'));
    fs.writeFileSync(path.join(tmp, 'target'), 'From: alerts@chase.com\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\nSubject: hello\n\nclick https://xn--chse-9na.com/login urgently verify now with your password');
    let pyOut = null;
    try { pyOut = JSON.parse(cp.execFileSync('python3', [path.join(tmp, 'scan.py'), path.join(tmp, 'target')], { timeout: 15000 }).toString()); }
    catch (e) { try { pyOut = JSON.parse(cp.execFileSync('python', [path.join(tmp, 'scan.py'), path.join(tmp, 'target')], { timeout: 15000 }).toString()); } catch {} }
    if (pyOut) {
      const nodeStrict = require('../sandbox/local-engine').scan(Buffer.from('From: alerts@chase.com\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\nSubject: hello\n\nclick https://xn--chse-9na.com/login urgently verify now with your password'), 'c.eml', ['chase.com'], { profile: 'strict' });
      const ok7 = pyOut.verdict === nodeStrict.verdict && pyOut.score === nodeStrict.score;
      console.log(`${ok7 ? 'PASS' : 'FAIL'} python scan.py parity => py ${pyOut.verdict}(${pyOut.score}) vs node ${nodeStrict.verdict}(${nodeStrict.score})`); if (!ok7) fail++;
    } else console.log('SKIP python scan.py parity (no python on PATH)');

    // Billing webhook (demo mode: admin header fires a fake checkout event, no Stripe needed)
    process.env.TEAMS_KEY = 'test-admin-key';
    const evt = JSON.stringify({ type: 'checkout.session.completed', data: { object: { customer_email: 'team@example.com' } } });
    res = await fetch(base + '/api/billing/webhook', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-teams-key': 'test-admin-key' }, body: evt });
    j = await res.json();
    const ok8 = res.status === 200 && typeof j.teams_key === 'string' && j.teams_key.startsWith('tm_');
    console.log(`${ok8 ? 'PASS' : 'FAIL'} POST /api/billing/webhook demo => issued ${ok8 ? 'tm_…' : JSON.stringify(j).slice(0, 120)}`); if (!ok8) fail++;

    // New key bypasses the rate limiter (prove validity with a scan using it)
    res = await fetch(base + '/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-teams-key': j.teams_key }, body: JSON.stringify({ emailText: 'From: a@b.com\nReceived: x\n\nhello https://example.com' }) });
    const ok9 = res.status === 200;
    console.log(`${ok9 ? 'PASS' : 'FAIL'} teams key bypasses rate limit => ${res.status}`); if (!ok9) fail++;

    // Unsigned webhook must fail
    res = await fetch(base + '/api/billing/webhook', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: evt });
    const ok10 = res.status === 401;
    console.log(`${ok10 ? 'PASS' : 'FAIL'} unsigned webhook rejected => ${res.status}`); if (!ok10) fail++;

    // Delete a report
    res = await fetch(base + '/api/analyze/report/' + rep.id, { method: 'DELETE' });
    const del = await res.json();
    res = await fetch(base + '/api/analyze/report/' + rep.id);
    const ok11 = del.ok === true && res.status === 404;
    console.log(`${ok11 ? 'PASS' : 'FAIL'} DELETE /api/analyze/report/:id => gone`); if (!ok11) fail++;

    // Sample gallery files served
    res = await fetch(base + '/samples/phishing.eml');
    const txt = await res.text();
    const ok12 = res.status === 200 && /chase-secure\.co/.test(txt);
    console.log(`${ok12 ? 'PASS' : 'FAIL'} GET /samples/phishing.eml => served`); if (!ok12) fail++;

    // --- Trust API (institutions sign messages) -----------------------------
    process.env.ADMIN_KEY = 'test-admin-key';

    // Admin key required to register
    res = await fetch(base + '/api/trust/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'Nope Bank' }) });
    fail += check(`POST /api/trust/register without admin => 401 (${res.status})`, res.status === 401);

    // Register a bank
    res = await fetch(base + '/api/trust/register', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-admin-key': 'test-admin-key' }, body: JSON.stringify({ name: 'GTBank', domains: ['gtbank.com'] }) });
    j = await res.json();
    const apiKey = j.api_key, secret = j.secret, instId = j.institution && j.institution.id;
    const okT1 = res.status === 201 && typeof apiKey === 'string' && apiKey.startsWith('dpiq_') && typeof secret === 'string' && secret.length >= 32;
    console.log(`${okT1 ? 'PASS' : 'FAIL'} POST /api/trust/register => ${instId || 'no id'} (api_key ${okT1 ? 'issued' : 'MISSING'})`); if (!okT1) fail++;

    // Seal a message -> get the link block appended below it
    res = await fetch(base + '/api/trust/seal', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey }, body: JSON.stringify({ channel: 'email', reference: 'stmt-2026-05', subject: 'Your May statement', recipient: 'customer@example.com' }) });
    j = await res.json();
    const token = j.token, verifyUrl = j.verify_url;
    const okT2 = res.status === 200 && typeof token === 'string' && token.includes('.') && j.signature && j.signature.text.includes(verifyUrl) && j.signature.html.includes(verifyUrl) && j.expires_at;
    console.log(`${okT2 ? 'PASS' : 'FAIL'} POST /api/trust/seal => token + signature block (${okT2 ? 'ok' : JSON.stringify(j).slice(0, 120)})`); if (!okT2) fail++;

    // The appended link resolves on the public /verify/:token path
    res = await fetch(base + '/verify/' + token);
    j = await res.json();
    const okT3 = res.status === 200 && j.valid === true && j.institution && j.institution.name === 'GTBank' && typeof j.message === 'string' && j.message.includes('GTBank');
    console.log(`${okT3 ? 'PASS' : 'FAIL'} GET /verify/:token => ${j.valid ? 'valid' : j.reason} :: ${(j.message || '').slice(0, 60)}…`); if (!okT3) fail++;

    // Recipient PII must never be embedded — the token rides in a public URL
    const payloadText = Buffer.from(token.split('.')[0], 'base64url').toString('utf8');
    const okT4 = /"iid"/.test(payloadText) && !payloadText.includes('customer@example.com') && !payloadText.includes('example.com') && !payloadText.includes('@');
    console.log(`${okT4 ? 'PASS' : 'FAIL'} seal token payload omits recipient PII => ${payloadText}`); if (!okT4) fail++;

    // A tampered token must fail verification
    const tampered = token.slice(0, -1) + (token.endsWith('A') ? 'B' : 'A');
    res = await fetch(base + '/api/trust/verify/' + tampered);
    j = await res.json();
    const okT5 = j.valid === false && j.reason === 'bad_signature';
    console.log(`${okT5 ? 'PASS' : 'FAIL'} tampered token => ${j.valid ? 'VALID?!' : j.reason}`); if (!okT5) fail++;

    // Unknown institution id (forged issuer) must fail
    const forged = Buffer.from(JSON.stringify({ v: 1, iid: 'inst_deadbeef', ch: 'email', ref: null, iat: 1, exp: 9999999999 })).toString('base64url') + '.signature';
    res = await fetch(base + '/api/trust/verify/' + forged);
    j = await res.json();
    const okT6 = j.valid === false && j.reason === 'unknown_institution';
    console.log(`${okT6 ? 'PASS' : 'FAIL'} forged issuer => ${j.valid ? 'VALID?!' : j.reason}`); if (!okT6) fail++;

    // Wrong API key cannot seal
    res = await fetch(base + '/api/trust/seal', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': 'dpiq_wrong' }, body: JSON.stringify({ channel: 'sms' }) });
    fail += check(`POST /api/trust/seal with bad key => 401 (${res.status})`, res.status === 401);

    // Revoked institution stops verifying
    res = await fetch(base + '/api/trust/institutions/' + instId, { method: 'DELETE', headers: { 'x-admin-key': 'test-admin-key' } });
    const revoked = await res.json();
    res = await fetch(base + '/api/trust/verify/' + token);
    j = await res.json();
    const okT7 = revoked.ok === true && j.valid === false && j.reason === 'unknown_institution';
    console.log(`${okT7 ? 'PASS' : 'FAIL'} revoke institution => subsequent verify rejected (${j.reason})`); if (!okT7) fail++;
  } finally { try { srv.closeAllConnections(); } catch {} srv.close(); }
  setTimeout(() => process.exit(fail ? 1 : 0), 100);
}

main().catch(e => { console.error('TEST CRASH', e); process.exit(1); });
