// Typed client for the Express API in backend/ (routes/analyze.js, routes/billing.js, routes/trust.js).
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

/** The Gemini-written explanation of a scan. Never overrides the engine's verdict/score. */
export interface NlVerdict {
  headline: string;
  summary: string;
  action: string;
  confidence: "low" | "medium" | "high";
  verdict: Verdict;
  risk_score: number;
  provider: string;
  model: string;
  generated_at: string;
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
  nl?: NlVerdict;
  // Present on stored reports (GET /api/analyze/report/:id), not on the
  // immediate scan response.
  filename?: string;
  t?: string;
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

/** One progress event from POST /api/analyze/stream (server-sent events). */
export type AgentRunEvent =
  | { type: "status"; step: string; label: string; state: "active" | "done"; detail?: string }
  | { type: "script"; profile: string }
  | { type: "script_line"; profile: string; line: string }
  | {
      type: "llm";
      provider: string;
      model: string;
      state: "trying" | "ok" | "failed";
      error?: string;
    };

/** Split one `event:`/`data:` SSE frame; ignores comments and keep-alives. */
function parseSseFrame(frame: string): { name: string; data: unknown } | null {
  let name = "message";
  const data: string[] = [];
  for (const line of frame.split("\n")) {
    if (line.startsWith("event:")) name = line.slice(6).trim();
    else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
  }
  if (data.length === 0) return null;
  try {
    return { name, data: JSON.parse(data.join("\n")) };
  } catch {
    return null;
  }
}

/**
 * Scan while watching the agent work: POSTs to the streaming endpoint and
 * reports each server-sent event as it lands, resolving with the finished
 * report. This replaces upload-percentage progress — the wait is the agent
 * writing and running its analyser, so that is what the UI should show.
 *
 * `fetch` (not XHR) drives this. If a server answers with plain JSON instead —
 * an older build, or a proxy that strips the event-stream content type — the
 * body is taken as the result, so the panel still works.
 */
export async function scanStream(
  input: ScanInput,
  options: {
    deep?: boolean;
    onEvent?: (event: AgentRunEvent) => void;
    signal?: AbortSignal;
  } = {},
): Promise<ScanResult> {
  const { file, emailText, filename } = input;
  const path = options.deep ? "/analyze/deep/stream" : "/analyze/stream";
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
  if (options.signal) init.signal = options.signal;

  const res = await fetch(`${BASE}${path}`, init);
  // A server that predates the streaming route (an older build, or a proxy in
  // the way) still answers the plain endpoint — fall back rather than fail.
  if (res.status === 404 || res.status === 405) {
    return scan(input, options.deep ? { deep: true } : {});
  }
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as { error?: string } | null;
    throw new Error(body?.error ?? `Request failed (${res.status})`);
  }

  const body = res.body;
  const isStream =
    !!body &&
    typeof body.getReader === "function" &&
    (res.headers.get("content-type") ?? "").includes("text/event-stream");
  if (!isStream || !body) return (await res.json()) as ScanResult;

  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let result: ScanResult | null = null;

  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let split = buffer.indexOf("\n\n");
    while (split !== -1) {
      const frame = parseSseFrame(buffer.slice(0, split));
      buffer = buffer.slice(split + 2);
      if (frame) {
        if (frame.name === "result") {
          result = frame.data as ScanResult;
        } else if (frame.name === "error") {
          const failure = frame.data as { error?: string };
          throw new Error(failure?.error ?? "The scan failed");
        } else {
          options.onEvent?.({ type: frame.name, ...(frame.data as object) } as AgentRunEvent);
        }
      }
      split = buffer.indexOf("\n\n");
    }
  }

  if (!result) throw new Error("The scan stream ended before a verdict was produced");
  return result;
}

/** GET /api/analyze/report/:id — full report with agent code. */
export async function fetchReport(id: string): Promise<ScanResult> {
  return toJson<ScanResult>(await fetch(`${BASE}/analyze/report/${encodeURIComponent(id)}`));
}

/** Public shareable report page rendered by Express from public/report.html. */
export function reportUrl(id: string) {
  return `/v/${id}`;
}

/** DELETE /api/analyze/report/:id — remove your report. */
export async function deleteReport(id: string): Promise<void> {
  const res = await fetch(`${BASE}/analyze/report/${encodeURIComponent(id)}`, { method: "DELETE" });
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as { error?: string } | null;
    throw new Error(body?.error ?? `Delete failed (${res.status})`);
  }
}
