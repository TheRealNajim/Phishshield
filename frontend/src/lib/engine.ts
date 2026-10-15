// PhishShield detection engine (client-side port of the heuristics in the brief).
export type Verdict = "Verified" | "Suspicious" | "Malicious";
export interface Reason { text: string; weight: number }
export interface ScanResult {
  id: string;
  verdict: Verdict;
  score: number;
  reasons: Reason[];
  iocs: { domains: string[]; ips: string[]; urls: string[] };
  agent_code: string;
  subject: string;
  from: string;
  at: number;
}

export const MALICIOUS_AT = 70;
export const SUSPICIOUS_AT = 40;

const BRANDS: Record<string, string> = {
  paypal: "paypal.com", chase: "chase.com", apple: "apple.com", microsoft: "microsoft.com",
  amazon: "amazon.com", google: "google.com", netflix: "netflix.com", wellsfargo: "wellsfargo.com",
  bankofamerica: "bankofamerica.com", dhl: "dhl.com", fedex: "fedex.com", linkedin: "linkedin.com",
  gtbank: "gtbank.com", kuda: "kuda.com", opay: "opayweb.com", moniepoint: "moniepoint.com",
  zenith: "zenithbank.com", firstbank: "firstbanknigeria.com",
};
const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy"];

export function normalize(s: string) {
  return s.toLowerCase().replace(/rn/g, "m").replace(/0/g, "o").replace(/1/g, "l").replace(/-/g, "");
}
export function levenshtein(a: string, b: string) {
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0]![j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      d[i]![j] = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length]![b.length]!;
}
const base = (domain: string) => domain.split(".").slice(-2).join(".");
const label = (domain: string) => base(domain).split(".")[0] ?? "";

export function lookalike(domain: string): string | null {
  const l = label(domain);
  for (const [brand, real] of Object.entries(BRANDS)) {
    if (base(domain) === real) return null;
    const n = normalize(l);
    if (n === brand || n.startsWith(brand) || (levenshtein(n, brand) <= 2 && brand.length > 4)) return real;
  }
  return null;
}

export function verdictFor(score: number): Verdict {
  return score >= MALICIOUS_AT ? "Malicious" : score >= SUSPICIOUS_AT ? "Suspicious" : "Verified";
}

export function analyze(text: string, strict = false): ScanResult {
  const reasons: Reason[] = [];
  const add = (t: string, w: number) => reasons.push({ text: t, weight: strict && w > 0 ? Math.round(w * 1.25) : w });
  const header = (h: string) => text.match(new RegExp(`^${h}:\\s*(.+)$`, "im"))?.[1]?.trim() ?? "";
  const from = header("From");
  const subject = header("Subject") || "(no subject)";
  const fromDomain = from.match(/@([\w.-]+)/)?.[1]?.toLowerCase() ?? "";
  const display = (from.split("<")[0] ?? "").replace(/"/g, "").trim().toLowerCase();

  const urls = [...new Set(text.match(/https?:\/\/[^\s"'<>\]]+/gi) ?? [])];
  const domains = [...new Set(urls.map((u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } }).filter(Boolean))];
  if (fromDomain) domains.unshift(fromDomain);
  const ips = [...new Set(text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? [])];

  const auth = text.toLowerCase();
  if (/spf=pass/.test(auth) && /dkim=pass/.test(auth)) add("SPF/DKIM passed", -15);
  if (/spf=(fail|softfail)/.test(auth)) add("SPF check failed", 25);
  if (/dkim=fail/.test(auth)) add("DKIM signature failed", 20);
  if (/dmarc=fail/.test(auth)) add("DMARC failed", 15);

  for (const d of new Set(domains)) {
    const real = lookalike(d);
    if (real) add(`Lookalike domain ${d} imitates ${real}`, 35);
  }
  for (const [brand, real] of Object.entries(BRANDS)) {
    if (display.includes(brand) && fromDomain && base(fromDomain) !== real)
      add(`Display name says "${brand}", came from ${fromDomain}`, 25);
  }
  for (const m of text.matchAll(/\[\[LINK\s+(\S+)\s+(\S+)\]\]|<a[^>]+href="([^"]+)"[^>]*>([^<]+)<\/a>/gi)) {
    const shown = (m[1] ?? m[4] ?? "").trim(); const href = (m[2] ?? m[3] ?? "").trim();
    const sd = shown.match(/([\w-]+\.)+[a-z]{2,}/i)?.[0]; let hd = "";
    try { hd = new URL(href).hostname; } catch { /* noop */ }
    if (sd && hd && base(sd.toLowerCase()) !== base(hd.toLowerCase())) add(`Link shows ${sd} but goes to ${hd}`, 30);
  }
  if (urls.some((u) => /https?:\/\/\d{1,3}(\.\d{1,3}){3}/.test(u))) add("Link points to a bare IP address", 25);
  if (domains.some((d) => SHORTENERS.includes(d))) add("URL shortener hides the destination", 15);
  if (/\b(bvn|nin|otp|one[- ]time password|pin)\b/i.test(text)) add("Asks for BVN/NIN/OTP/PIN", 30);
  if (/(lottery|you have won|claim your prize|inheritance)/i.test(text)) add("Lottery / prize scam language", 25);
  if (/(urgent|immediately|within 24 hours|suspended|verify your account)/i.test(text)) add("Urgency / account-threat language", 15);
  if (/\.(exe|scr|js|vbs|iso|html?)\b/i.test(text) && /attach/i.test(text)) add("Risky attachment type", 20);

  const score = Math.max(0, reasons.reduce((s, r) => s + r.weight, 0));
  return {
    id: Math.random().toString(36).slice(2, 10),
    verdict: verdictFor(score), score, reasons, subject, from,
    iocs: { domains: [...new Set(domains)], ips, urls },
    agent_code: agentCode(strict, domains, urls),
    at: Date.now(),
  };
}

function agentCode(strict: boolean, domains: string[], urls: string[]) {
  return `# scan.py — written by PhishShield agent (${strict ? "strict" : "standard"} variant)
# runs in micro-VM, egress=[]
import json, re, email
msg = email.message_from_file(open("/tmp/target.eml"))
domains = ${JSON.stringify(domains.slice(0, 6))}
urls = ${JSON.stringify(urls.slice(0, 4))}
score, reasons = 0, []
for d in domains:
    if lookalike(normalize(d)): score += 35; reasons.append(f"lookalike {d}")
if re.search(r"spf=(fail|softfail)", str(msg)): score += 25
${strict ? "score = int(score * 1.25)  # harsher weights\n" : ""}print(json.dumps({"score": score, "verdict": verdict(score, 70, 40)}))`;
}
