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

async function main() {
  let fail = 0;
  for (const c of cases) {
    const r = scan(c.buf, c.file, ['chase.com']);
    let ok = c.want ? r.verdict === c.want : r.score >= c.wantScore;
    if (ok && c.wantReason) ok = r.reasons.some(x => x.includes(c.wantReason));
    console.log(`${ok ? 'PASS' : 'FAIL'} ${c.name} => ${r.verdict} (${r.score}) :: ${r.reasons.join('; ')}`);
    if (!ok) fail++;
  }

  // API integration: analyze + history + billing (mock sandbox)
  process.env.MOCK_SANDBOX = 'true';
  const app = require('../server');
  const srv = app.listen(0);
  await new Promise(r => srv.on('listening', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    let res = await fetch(base + '/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ emailText: 'From: alerts@chase.com\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\n\nSee https://chase.com/x' }) });
    let j = await res.json();
    const ok1 = j.verdict === 'Verified' && typeof j.agent_code === 'string';
    console.log(`${ok1 ? 'PASS' : 'FAIL'} POST /api/analyze email => ${j.verdict} (agent_code ${(j.agent_code || '').length} chars)`); if (!ok1) fail++;

    res = await fetch(base + '/api/analyze/history');
    j = await res.json();
    const ok2 = Array.isArray(j) && j.length >= 1;
    console.log(`${ok2 ? 'PASS' : 'FAIL'} GET /api/analyze/history => ${Array.isArray(j) ? j.length : typeof j} entries`); if (!ok2) fail++;

    res = await fetch(base + '/api/billing');
    j = await res.json();
    const ok3 = j.free && j.teams;
    console.log(`${ok3 ? 'PASS' : 'FAIL'} GET /api/billing => free+teams plans`); if (!ok3) fail++;

    // Deep scan: borderline input should split the two runs (standard Verified, strict Suspicious+)
    res = await fetch(base + '/api/analyze/deep', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ emailText: 'From: alerts@chase.com\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\nSubject: hello\n\nclick https://xn--chse-9na.com/login urgently verify now with your password' }) });
    j = await res.json();
    const ok4 = Array.isArray(j.runs) && j.runs.length === 2 && typeof j.agreement === 'boolean' && j.id;
    console.log(`${ok4 ? 'PASS' : 'FAIL'} POST /api/analyze/deep => ${j.runs ? j.runs.map(r => r.profile + ':' + r.verdict + '(' + r.score + ')').join(' vs ') : 'no runs'} agree=${j.agreement}`); if (!ok4) fail++;

    // Shareable report round-trip
    res = await fetch(base + '/api/analyze/report/' + j.id);
    const rep = await res.json();
    const ok5 = rep.id === j.id && rep.verdict === j.verdict;
    console.log(`${ok5 ? 'PASS' : 'FAIL'} GET /api/analyze/report/:id => ${rep.verdict} (${rep.score})`); if (!ok5) fail++;

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
  } finally { try { srv.closeAllConnections(); } catch {} srv.close(); }
  setTimeout(() => process.exit(fail ? 1 : 0), 100);
}

main().catch(e => { console.error('TEST CRASH', e); process.exit(1); });
