// Wrapper: real CreateOS micro-VM in live mode, local regex engine in mock mode.
// Live: CREATEOS_SANDBOX_API_KEY + MOCK_SANDBOX=false. SDK is ESM-only -> dynamic import.
const { buildScanPy } = require('../agent/scan-generator');

const SEV = { Verified: 0, Suspicious: 1, Malicious: 2 };

async function analyzeLive(buffer, filename, agentCode) {
  const { CreateosSandboxClient } = await import('@nodeops-createos/sandbox');
  const client = new CreateosSandboxClient(); // reads CREATEOS_SANDBOX_API_KEY / CREATEOS_SANDBOX_BASE_URL
  const sandbox = await client.createSandbox({
    shape: 's-1vcpu-1gb',
    rootfs: 'devbox:1',
    egress: [], // zero egress: untrusted file + agent code can't reach the internet
  });
  try {
    await sandbox.files.upload('/tmp/target', buffer);
    await sandbox.files.upload('/tmp/scan.py', agentCode);
    const { result } = await sandbox.runCommand('python3', ['/tmp/scan.py', '/tmp/target'], { timeoutMs: 60000 });
    if (result.exit_code !== 0) throw new Error('scan.py failed: ' + (result.stderr || result.stdout || '').slice(0, 500));
    const parsed = JSON.parse(result.stdout);
    parsed.agent_code = agentCode;
    parsed.mode = 'createos-sandbox (live micro-VM)';
    return parsed;
  } finally {
    await sandbox.destroy().catch(() => {});
  }
}

async function runOne(buffer, filename, profile, opts = {}) {
  const agentCode = buildScanPy(filename, profile);
  if (process.env.MOCK_SANDBOX === 'false') {
    try {
      const r = await analyzeLive(buffer, filename, agentCode);
      r.profile = profile;
      return r;
    } catch (e) {
      if (!process.env.CREATEOS_SANDBOX_API_KEY) {
        const local = require('./local-engine');
        const r = local.scan(buffer, filename, opts.knownDomains, { profile });
        r.agent_code = agentCode;
        r.mode = 'mock-sandbox (local, no API key)';
        return r;
      }
      throw e;
    }
  }
  const local = require('./local-engine');
  const result = local.scan(buffer, filename, opts.knownDomains, { profile });
  result.agent_code = agentCode;
  result.mode = 'mock-sandbox (local)';
  return result;
}

async function analyzeBuffer(buffer, filename, opts = {}) {
  return runOne(buffer, filename, 'standard', opts);
}

// Deep scan: two analyzer variants (standard + strict) run in two parallel
// sandboxes. Verdict = highest severity; reasons = union, strict-first.
async function analyzeDeep(buffer, filename, opts = {}) {
  const [a, b] = await Promise.all([
    runOne(buffer, filename, 'standard', opts),
    runOne(buffer, filename, 'strict', opts),
  ]);
  const top = SEV[b.verdict] > SEV[a.verdict] ? b : a;
  const seen = new Set();
  const reasons = [...b.reasons, ...a.reasons].filter(r => !seen.has(r) && seen.add(r));
  return {
    verdict: top.verdict,
    score: Math.max(a.score, b.score),
    reasons,
    iocs: top.iocs,
    kind: a.kind,
    size: a.size,
    mode: a.mode,
    profile: 'deep',
    runs: [
      { profile: 'standard', verdict: a.verdict, score: a.score },
      { profile: 'strict', verdict: b.verdict, score: b.score },
    ],
    agreement: a.verdict === b.verdict,
    agent_code: a.agent_code,
    agent_code_strict: b.agent_code,
  };
}

module.exports = { analyzeBuffer, analyzeDeep };
