'use strict';
// Quick check that the Gemini natural-language verdict is wired up.
// Usage: cd backend && npm run llm:check
require('dotenv').config();

const llm = require('../agent/llm');

// A fake scan result so we can exercise the LLM without touching a file.
const SAMPLE = {
  verdict: 'Malicious',
  score: 210,
  kind: 'email',
  filename: 'chase-alert.eml',
  mode: 'mock-sandbox (local)',
  profile: 'standard',
  reasons: [
    'SPF failed',
    'Lookalike sender domain: chase-secure.co',
    'Link shows chase.com but goes to 192.168.1.99',
    'Link goes to a bare IP address (192.168.1.99)',
    'Urgent tone + credential (PIN/OTP) request',
  ],
  iocs: {
    sha256: '0'.repeat(64),
    domains: ['chase-secure.co'],
    urls: ['http://192.168.1.99/login'],
  },
};

/** Ask Gemini which models this key can use (helps when GEMINI_MODEL 404s). */
async function listModels() {
  const base = (process.env.GEMINI_BASE_URL || 'https://generativelanguage.googleapis.com').replace(/\/+$/, '');
  try {
    const res = await fetch(`${base}/v1beta/models?pageSize=200`, {
      headers: { 'x-goog-api-key': process.env.GEMINI_API_KEY },
    });
    if (!res.ok) return [];
    const body = await res.json();
    return (body.models || [])
      .filter((m) => (m.supportedGenerationMethods || []).includes('generateContent'))
      .map((m) => String(m.name).replace(/^models\//, ''));
  } catch {
    return [];
  }
}

(async () => {
  if (!llm.isConfigured()) {
    console.error('✗ GEMINI_API_KEY is not set.');
    console.error('  Add it to backend/.env — get a free key at https://aistudio.google.com/apikey');
    process.exit(1);
  }

  console.log(`→ model chain: ${llm.modelChain().join(' → ')}`);
  try {
    const nl = await llm.explain(SAMPLE);
    console.log('\n✓ Natural-language verdict is working\n');
    console.log('headline   :', nl.headline);
    console.log('summary    :', nl.summary);
    console.log('action     :', nl.action);
    console.log('confidence :', nl.confidence);
    console.log('model      :', nl.model);
  } catch (e) {
    console.error(`\n✗ ${e.code || 'ERROR'}: ${e.message}`);
    const models = await listModels();
    if (models.length) {
      console.error('\nModels available to this key (set GEMINI_MODEL to one of these):');
      for (const m of models.slice(0, 25)) console.error('  -', m);
    }
    process.exit(1);
  }
})();
