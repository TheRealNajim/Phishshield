// Typed client for the Express API in the repo root (routes/analyze.js, routes/billing.js).
// Same-origin by default: Express serves this build, and `npm run dev` proxies /api.
export type Verdict = "Verified" | "Suspicious" | "Malicious";

export interface Iocs {
  sha256?: string;
  urls: string[];
  domains: string[];
}

export interface ScanRun {
  profile: string;
  verdict: Verdict;
  score: number;
}

export interface ScanResult {
  id: string;
  verdict: Verdict;
  score: number;
  reasons: string[];
  iocs: Iocs;
  kind: string;
  size?: number;
  mode?: string;
  profile?: string;
  agent_code?: string;
  runs?: ScanRun[];
  agreement?: boolean;
  deep?: boolean;
}

// GET /api/analyze/history trims agent_code and flags has_code instead.
export interface ScanSummary extends Omit<ScanResult, "agent_code"> {
  t: string;
  filename: string;
  has_code?: boolean;
}

export interface Billing {
  free: { name: string; price: number; limit: string };
  teams: {
    name: string;
    price: string;
    perks: string[];
    checkout: string | null;
    hint?: string;
  };
}

export interface Health {
  ok: boolean;
  mock: boolean;
}

const BASE = (import.meta.env?.["VITE_API_BASE"] as string | undefined) ?? "/api";

async function toJson<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as { error?: string } | null;
    throw new Error(body?.error ?? `Request failed (${res.status})`);
  }
  return (await res.json()) as T;
}

export async function fetchHistory(): Promise<ScanSummary[]> {
  return toJson<ScanSummary[]>(await fetch(`${BASE}/analyze/history`));
}

export async function fetchHealth(): Promise<Health> {
  return toJson<Health>(await fetch(`${BASE}/health`));
}

export async function fetchBilling(): Promise<Billing> {
  return toJson<Billing>(await fetch(`${BASE}/billing`));
}

export async function fetchSample(name: "clean" | "phishing" | "borderline"): Promise<string> {
  const res = await fetch(`/samples/${name}.eml`);
  if (!res.ok) throw new Error(`Sample ${name} unavailable (${res.status})`);
  return res.text();
}

export interface ScanInput {
  file?: File | null;
  emailText?: string;
  filename?: string;
}

export async function scan(
  { file, emailText, filename }: ScanInput,
  options: { deep?: boolean } = {},
): Promise<ScanResult> {
  const path = options.deep ? "/analyze/deep" : "/analyze";
  let init: RequestInit;

  if (file) {
    const form = new FormData();
    form.append("file", file);
    init = { method: "POST", body: form };
  } else {
    init = {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ emailText: emailText ?? "", filename: filename ?? "email.eml" }),
    };
  }

  return toJson<ScanResult>(await fetch(`${BASE}${path}`, init));
}

/** Public shareable report page rendered by Express from public/report.html. */
export function reportUrl(id: string) {
  return `/v/${id}`;
}
