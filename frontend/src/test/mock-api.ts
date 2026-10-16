import { vi } from "vitest";

import type { ScanSummary } from "@/lib/api";

const HOUR = 60 * 60 * 1000;
const MINUTE = 60 * 1000;

export const historyFixture = (now = Date.now()): ScanSummary[] => [
  {
    id: "r1",
    t: new Date(now - 2 * HOUR).toISOString(),
    filename: "chase-alert.eml",
    verdict: "Malicious",
    score: 200,
    reasons: ["Lookalike domain chase-secure.co imitates chase.com", "SPF check failed"],
    iocs: { sha256: "deadbeef", domains: ["chase-secure.co"], urls: ["http://192.168.1.99/login"] },
    kind: "email",
    size: 2048,
    mode: "mock-sandbox (local)",
    has_code: true,
  },
  {
    id: "r2",
    t: new Date(now - 30 * MINUTE).toISOString(),
    filename: "newsletter.eml",
    verdict: "Verified",
    score: 0,
    reasons: ["SPF/DKIM passed"],
    iocs: { sha256: "cafe", domains: ["github.com"], urls: ["https://github.com/notifications"] },
    kind: "email",
    size: 1024,
    mode: "mock-sandbox (local)",
    has_code: true,
  },
];

export const scanFixture = {
  id: "new1",
  verdict: "Malicious" as const,
  score: 200,
  reasons: ["Lookalike domain chase-secure.co imitates chase.com", "Asks for BVN/NIN/OTP/PIN"],
  iocs: { sha256: "deadbeef", domains: ["chase-secure.co"], urls: ["http://192.168.1.99/login"] },
  kind: "email",
  size: 512,
  mode: "mock-sandbox (local)",
  agent_code: "# scan.py — written by PhishShield agent (standard variant)",
  nl: {
    headline: "This email is a phishing attempt impersonating Chase.",
    summary: "It comes from a lookalike domain and pressures you to hand over your PIN and OTP.",
    action: "Do not reply or click anything. Delete it and call Chase on the number on your card.",
    confidence: "high" as const,
    verdict: "Malicious" as const,
    risk_score: 200,
    provider: "gemini",
    model: "gemini-3-flash-preview",
    generated_at: new Date(0).toISOString(),
  },
};

export const deepScanFixture = {
  ...scanFixture,
  reasons: [...scanFixture.reasons, "Urgency / account-threat language"],
  runs: [
    { profile: "standard", verdict: "Suspicious" as const, score: 55 },
    { profile: "strict", verdict: "Malicious" as const, score: 69 },
  ],
  agreement: false,
  deep: true,
};

function json(body: unknown, status = 200) {
  // Minimal stand-in for a Response — jsdom exposes no fetch/Response implementation.
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  } as unknown as Response;
}

export interface StubOptions {
  history?: ScanSummary[];
  scanResult?: unknown;
  scanStatus?: number;
  scanError?: string;
}

/** Replaces global fetch with a stub covering every endpoint the dashboard calls. */
export function stubApi(options: StubOptions = {}) {
  let history = options.history ?? historyFixture();

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const method = (init?.method ?? "GET").toUpperCase();

    if (url.includes("/api/analyze/history")) return json(history);
    if (url.includes("/api/analyze/report/") && method === "GET") {
      const id = url.split("/").pop() ?? "";
      const found = history.find((r) => r.id === id);
      if (!found) return json({ error: "Report not found" }, 404);
      return json({ ...scanFixture, ...found, agent_code: "# scan.py — written by the agent" });
    }
    if (url.includes("/api/analyze/report/") && method === "DELETE") {
      const id = url.split("/").pop() ?? "";
      if (!history.some((r) => r.id === id)) return json({ error: "Report not found" }, 404);
      // Reassign (rather than splice) so refetches yield a new array,
      // exactly like fresh JSON from the real backend.
      history = history.filter((r) => r.id !== id);
      return json({ ok: true });
    }
    if (url.includes("/api/health")) return json({ ok: true, mock: true });
    if (url.includes("/api/billing")) {
      return json({
        free: { name: "Personal", price: 0, limit: "30 scans/hour" },
        teams: {
          name: "Teams",
          price: "$19/mo",
          perks: ["unlimited scans"],
          checkout: "https://example.test/pay",
        },
      });
    }
    if (url.includes("/samples/")) return json('From: "Chase Bank" <alerts@chase-secure.co>');
    if (url.includes("/api/analyze/deep")) return json(options.scanResult ?? deepScanFixture);
    if (url.includes("/api/analyze")) {
      if (options.scanStatus && options.scanStatus >= 400) {
        return json({ error: options.scanError ?? "boom" }, options.scanStatus);
      }
      if (method === "POST") return json(options.scanResult ?? scanFixture);
    }
    throw new Error(`unstubbed request: ${method} ${url}`);
  });

  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}
