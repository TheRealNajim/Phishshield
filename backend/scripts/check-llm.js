'use strict';
// Quick check that the natural-language verdict is wired up.
// Usage: cd backend && npm run llm:check
//
// Works for both provider shapes. With LLM_API_KEY set (Groq by default) it
// exercises the OpenAI-compatible path; with GEMINI_API_KEY it exercises Gemini.
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
async function listGeminiModels() {
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

/** Ask an OpenAI-compatible endpoint which models this key can use. */
async function listOpenAIModels() {
  const base = (process.env.LLM_BASE_URL || 'https://api.groq.com/openai/v1').replace(/\/+$/, '');
  const key = (process.env.LLM_API_KEY || process.env.GROQ_API_KEY || '').trim();
  try {
    const res = await fetch(`${base}/models`, { headers: { authorization: `Bearer ${key}` } });
    if (!res.ok) return [];
    const body = await res.json();
    return (body.data || []).map((m) => String(m.id));
  } catch {
    return [];
  }
}

(async () => {
  const chain = llm.providerChain();
  if (!chain.length) {
    console.error('✗ No LLM provider is configured.');
    console.error('  Groq (free, fast):  LLM_API_KEY=gsk_...   get one at https://console.groq.com/keys');
    console.error('  Gemini:             GEMINI_API_KEY=...    get one at https://aistudio.google.com/apikey');
    process.exit(1);
  }

  console.log(`→ providers  : ${chain.map((p) => p.name).join(' → ')}  (primary: ${llm.primaryProvider()})`);
  console.log(`→ model chain: ${llm.modelChain().join(' → ')}`);

  try {
    const nl = await llm.explain(SAMPLE, {
      onAttempt: (e) =>
        console.log(`   … ${e.provider}/${e.model}: ${e.state}${e.error ? ` — ${e.error}` : ''}`),
    });
    console.log('\n✓ Natural-language verdict is working\n');
    console.log('headline   :', nl.headline);
    console.log('summary    :', nl.summary);
    console.log('action     :', nl.action);
    console.log('confidence :', nl.confidence);
    console.log('provider   :', nl.provider);
    console.log('model      :', nl.model);
  } catch (e) {
    console.error(`\n✗ ${e.code || 'ERROR'}: ${e.message}`);
    if (chain.some((p) => p.name === 'openai')) {
      const models = await listOpenAIModels();
      if (models.length) {
        console.error('\nModels available to this key (set LLM_MODEL to one of these):');
        for (const m of models.slice(0, 25)) console.error('  -', m);
      }
    }
    if (chain.some((p) => p.name === 'gemini')) {
      const models = await listGeminiModels();
      if (models.length) {
        console.error('\nGemini models available to this key (set GEMINI_MODEL to one of these):');
        for (const m of models.slice(0, 25)) console.error('  -', m);
      }
    }
    process.exit(1);
  }
})();
