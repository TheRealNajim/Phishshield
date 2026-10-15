import { describe, expect, it } from "vitest";

import type { ScanSummary } from "./api";
import {
  DAY_MS,
  buildActivity,
  buildIndicators,
  buildSources,
  buildStats,
  buildTrend,
  primaryCategory,
  relativeTime,
  scansToCsv,
  severityDistribution,
  threatCategories,
  topStrings,
  trendPolyline,
  uniqueIocs,
  windowedChange,
} from "./threat-stats";

const NOW = Date.parse("2026-10-15T12:00:00.000Z");

function scan(
  over: Partial<ScanSummary> & { verdict: ScanSummary["verdict"]; t: string },
): ScanSummary {
  return {
    id: over.id ?? Math.random().toString(36).slice(2),
    score: over.score ?? 0,
    reasons: over.reasons ?? [],
    iocs: over.iocs ?? { urls: [], domains: [] },
    kind: over.kind ?? "email",
    filename: over.filename ?? "sample.eml",
    ...over,
  } as ScanSummary;
}

const HOUR = 60 * 60 * 1000;

describe("buildStats", () => {
  it("counts severities across the whole history", () => {
    const stats = buildStats(
      [
        scan({ verdict: "Malicious", t: new Date(NOW - HOUR).toISOString() }),
        scan({ verdict: "Malicious", t: new Date(NOW - 3 * HOUR).toISOString() }),
        scan({ verdict: "Suspicious", t: new Date(NOW - 4 * HOUR).toISOString() }),
        scan({ verdict: "Verified", t: new Date(NOW - 5 * HOUR).toISOString() }),
      ],
      NOW,
    );

    expect(stats.critical).toBe(2);
    expect(stats.suspicious).toBe(1);
    expect(stats.scans).toBe(4);
  });

  it("reports +100% for fresh activity with no 24h baseline", () => {
    const stats = buildStats(
      [scan({ verdict: "Malicious", t: new Date(NOW - HOUR).toISOString() })],
      NOW,
    );
    expect(stats.criticalDelta).toBe(100);
  });

  it("reports 0% when there is no activity at all", () => {
    const stats = buildStats([], NOW);
    expect(stats.criticalDelta).toBe(0);
    expect(stats.scansDelta).toBe(0);
  });

  it("computes the 24h change against the previous window", () => {
    const stats = buildStats(
      [
        scan({ verdict: "Malicious", t: new Date(NOW - HOUR).toISOString() }),
        scan({ verdict: "Malicious", t: new Date(NOW - 2 * HOUR).toISOString() }),
        scan({ verdict: "Malicious", t: new Date(NOW - DAY_MS - HOUR).toISOString() }),
      ],
      NOW,
    );

    expect(stats.critical).toBe(3);
    expect(stats.criticalDelta).toBe(100); // 2 in the last 24h vs 1 before
  });

  it("compares an arbitrary window against the one before it", () => {
    const scans = [
      scan({ verdict: "Malicious", t: new Date(NOW - HOUR).toISOString() }),
      scan({ verdict: "Malicious", t: new Date(NOW - DAY_MS - HOUR).toISOString() }),
      scan({ verdict: "Malicious", t: new Date(NOW - DAY_MS - 2 * HOUR).toISOString() }),
    ];
    // 1 in the last day vs 2 in the day before: -50%.
    expect(windowedChange((s) => s.length, scans, NOW, DAY_MS)).toBe(-50);
    expect(windowedChange((s) => s.length, [], NOW, DAY_MS)).toBe(0);
  });

  it("counts unique indicators only once", () => {
    const iocs = uniqueIocs([
      scan({
        verdict: "Malicious",
        t: new Date(NOW).toISOString(),
        iocs: {
          domains: ["chase-secure.co", "chase-secure.co"],
          urls: ["http://chase-secure.co/l"],
          sha256: "abc",
        },
      }),
      scan({
        verdict: "Suspicious",
        t: new Date(NOW).toISOString(),
        iocs: { domains: ["chase-secure.co"], urls: [], sha256: "abc" },
      }),
    ]);

    expect(iocs).toEqual(["abc", "chase-secure.co", "http://chase-secure.co/l"]);
  });
});

describe("severityDistribution", () => {
  it("returns zeros for empty history", () => {
    expect(severityDistribution([])).toEqual({ critical: 0, high: 0, low: 0 });
  });

  it("always sums to 100 percent", () => {
    const scans = [
      scan({ verdict: "Malicious", t: new Date(NOW).toISOString() }),
      scan({ verdict: "Suspicious", t: new Date(NOW).toISOString() }),
      scan({ verdict: "Suspicious", t: new Date(NOW).toISOString() }),
      scan({ verdict: "Verified", t: new Date(NOW).toISOString() }),
      scan({ verdict: "Verified", t: new Date(NOW).toISOString() }),
      scan({ verdict: "Verified", t: new Date(NOW).toISOString() }),
    ];
    const dist = severityDistribution(scans);

    expect(dist.critical + dist.high + dist.low).toBe(100);
    expect(dist).toEqual({ critical: 17, high: 33, low: 50 });
  });

  it("keeps a single severity at 100 percent", () => {
    const scans = [1, 2, 3].map(() =>
      scan({ verdict: "Verified", t: new Date(NOW).toISOString() }),
    );
    expect(severityDistribution(scans)).toEqual({ critical: 0, high: 0, low: 100 });
  });
});

describe("buildTrend", () => {
  it("spans the chart viewBox and labels today's bucket last", () => {
    const scans = [
      scan({ verdict: "Malicious", t: new Date(NOW - 2 * DAY_MS).toISOString() }),
      scan({ verdict: "Malicious", t: new Date(NOW - 2 * DAY_MS).toISOString() }),
      scan({ verdict: "Suspicious", t: new Date(NOW - HOUR).toISOString() }),
    ];
    const points = buildTrend(scans, 7, NOW);

    expect(points).toHaveLength(7);
    expect(points.at(0)).toMatchObject({ x: 0 });
    expect(points.at(-1)).toMatchObject({ x: 430, label: 1 });
    expect(points.at(-3)).toMatchObject({ label: 2 });
    // The busier day sits higher on the chart, so it has the smaller y.
    expect(points.at(-3)!.y).toBeLessThan(points.at(-1)!.y);
  });

  it("flattens to the baseline with no data", () => {
    const points = buildTrend([], 7, NOW);
    expect(new Set(points.map((p) => p.y))).toEqual(new Set([230]));
    expect(trendPolyline(points)).toContain("430,230");
  });

  it("ignores scans older than the window", () => {
    const points = buildTrend(
      [scan({ verdict: "Malicious", t: new Date(NOW - 30 * DAY_MS).toISOString() })],
      7,
      NOW,
    );
    expect(points.every((p) => p.label === 0)).toBe(true);
  });
});

describe("buildActivity", () => {
  it("buckets a single day into 24 hourly buckets", () => {
    const buckets = buildActivity(
      [
        scan({ verdict: "Malicious", t: new Date(NOW - HOUR).toISOString() }),
        scan({ verdict: "Verified", t: new Date(NOW - 2 * HOUR).toISOString() }),
      ],
      NOW,
      1,
    );

    expect(buckets).toHaveLength(24);
    expect(buckets.reduce((n, b) => n + b.scans, 0)).toBe(2);
    expect(buckets.reduce((n, b) => n + b.threats, 0)).toBe(1);
  });

  it("buckets a week into daily buckets and ignores out-of-range scans", () => {
    const buckets = buildActivity(
      [
        scan({ verdict: "Suspicious", t: new Date(NOW - HOUR).toISOString() }),
        scan({ verdict: "Malicious", t: new Date(NOW - 30 * DAY_MS).toISOString() }),
      ],
      NOW,
      7,
    );

    expect(buckets).toHaveLength(7);
    expect(buckets.reduce((n, b) => n + b.scans, 0)).toBe(1);
    expect(buckets.reduce((n, b) => n + b.threats, 0)).toBe(1);
  });

  it("switches to weekly buckets for long ranges", () => {
    const buckets = buildActivity(
      [scan({ verdict: "Verified", t: new Date(NOW - HOUR).toISOString() })],
      NOW,
      90,
    );

    expect(buckets).toHaveLength(Math.ceil(90 / 7));
    expect(buckets.reduce((n, b) => n + b.scans, 0)).toBe(1);
  });
});

describe("threatCategories", () => {
  it("matches recurring patterns and lets categories overlap", () => {
    const scans = [
      scan({
        verdict: "Malicious",
        t: new Date(NOW).toISOString(),
        reasons: ["Lookalike domain chase-secure.co imitates chase.com"],
        iocs: { domains: ["chase-secure.co"], urls: ["http://chase-secure.co/login"] },
      }),
      scan({
        verdict: "Suspicious",
        t: new Date(NOW).toISOString(),
        reasons: ["Asks for BVN/NIN/OTP/PIN"],
        iocs: { domains: [], urls: [] },
      }),
    ];
    const counts = Object.fromEntries(threatCategories(scans).map((c) => [c.name, c.count]));

    expect(counts["Brand impersonation"]).toBe(1);
    expect(counts["Suspicious links"]).toBe(1);
    expect(counts["Credential theft"]).toBe(1);
    expect(counts["Lookalike domains"]).toBe(1);
  });

  it("returns zeros when nothing matches", () => {
    const scans = [scan({ verdict: "Verified", t: new Date(NOW).toISOString() })];
    expect(threatCategories(scans).every((c) => c.count === 0)).toBe(true);
  });

  it("picks the first matching pattern as the primary category", () => {    const flagged = scan({
      verdict: "Malicious",
      t: new Date(NOW).toISOString(),
      reasons: ["Lookalike domain chase-secure.co imitates chase.com"],
      iocs: { domains: ["chase-secure.co"], urls: [] },
    });
    expect(primaryCategory(flagged)).toBe("Brand impersonation");

    const clean = scan({ verdict: "Verified", t: new Date(NOW).toISOString() });
    expect(primaryCategory(clean)).toBe("No significant indicators");

    const unknown = scan({
      verdict: "Suspicious",
      t: new Date(NOW).toISOString(),
      reasons: ["Something odd"],
      iocs: { domains: [], urls: [] },
    });
    expect(primaryCategory(unknown)).toBe("Unclassified");
  });
});

describe("buildSources", () => {
  const lookalike = scan({
    id: "s1",
    verdict: "Malicious",
    t: new Date(NOW - HOUR).toISOString(),
    filename: "chase-alert.eml",
    reasons: ["Lookalike domain chase-secure.co imitates chase.com"],
    iocs: { domains: ["chase-secure.co"], urls: ["http://192.168.1.99/login"] },
  });
  const repeat = scan({
    id: "s2",
    verdict: "Suspicious",
    t: new Date(NOW - 2 * HOUR).toISOString(),
    filename: "chase-alert-2.eml",
    reasons: ["Suspicious link to chase-secure.co"],
    iocs: { domains: ["chase-secure.co"], urls: [] },
  });
  const clean = scan({
    verdict: "Verified",
    t: new Date(NOW - 3 * HOUR).toISOString(),
    filename: "newsletter.eml",
    reasons: ["SPF/DKIM passed"],
    iocs: { domains: ["github.com"], urls: [] },
  });

  it("groups hosts across scans with worst verdict, counts and timestamps", () => {
    const records = buildSources([lookalike, repeat, clean]);
    const entry = records.find((r) => r.source === "chase-secure.co")!;

    expect(records.map((r) => r.source).sort()).toEqual(
      ["192.168.1.99", "chase-secure.co", "github.com"].sort(),
    );
    expect(entry.scans).toBe(2);
    expect(entry.verdict).toBe("Malicious");
    expect(entry.type).toBe("Lookalike domain");
    expect(entry.brand).toBe("chase.com");
    expect(entry.lastSeen).toBeGreaterThan(entry.firstSeen);
    expect(entry.score).toBe(0);
    expect(entry.evidence.length).toBeGreaterThan(0);
    expect(entry.reports.map((r) => r.id).sort()).toEqual(["s1", "s2"]);
  });

  it("types plain link hosts and clean observed domains honestly", () => {
    const records = buildSources([lookalike, clean]);
    const bySource = Object.fromEntries(records.map((r) => [r.source, r]));

    expect(bySource["192.168.1.99"]?.type).toBe("Link destination");
    expect(bySource["192.168.1.99"]?.verdict).toBe("Malicious");
    expect(bySource["github.com"]?.type).toBe("Observed domain");
    expect(bySource["github.com"]?.verdict).toBe("Verified");
    expect(bySource["github.com"]?.brand).toBeNull();
  });

  it("sorts worst verdicts first", () => {
    const records = buildSources([clean, lookalike]);
    expect(records[0]?.verdict).toBe("Malicious");
  });
});

describe("buildIndicators", () => {
  const evil = scan({
    id: "e1",
    verdict: "Malicious",
    t: new Date(NOW - HOUR).toISOString(),
    filename: "chase-alert.eml",
    reasons: ["Lookalike domain chase-secure.co imitates chase.com"],
    iocs: {
      sha256: "deadbeef",
      domains: ["chase-secure.co"],
      urls: ["http://192.168.1.99/login"],
    },
  });
  const clean = scan({
    id: "e2",
    verdict: "Verified",
    t: new Date(NOW - 2 * HOUR).toISOString(),
    filename: "newsletter.eml",
    reasons: ["SPF/DKIM passed"],
    iocs: { sha256: "cafe", domains: ["github.com"], urls: [] },
  });

  it("lists domains, URLs, IP hosts and hashes with per-artifact assessment", () => {
    const records = buildIndicators([evil, clean]);
    const byValue = Object.fromEntries(records.map((r) => [r.value, r]));

    expect(records).toHaveLength(6);
    expect(byValue["chase-secure.co"]?.type).toBe("Domain");
    expect(byValue["chase-secure.co"]?.assessment).toBe("Malicious");
    expect(byValue["http://192.168.1.99/login"]?.type).toBe("URL");
    expect(byValue["192.168.1.99"]?.type).toBe("IP address");
    expect(byValue["192.168.1.99"]?.assessment).toBe("Unassessed");
    expect(byValue["deadbeef"]?.type).toBe("SHA-256");
    expect(byValue["deadbeef"]?.assessment).toBe("Unassessed");
    expect(byValue["github.com"]?.assessment).toBe("Unassessed");
  });

  it("counts linked reports and tracks first and last sightings", () => {
    const again = scan({
      id: "e3",
      verdict: "Suspicious",
      t: new Date(NOW - 3 * HOUR).toISOString(),
      filename: "chase-again.eml",
      reasons: ["Odd link"],
      iocs: { domains: ["chase-secure.co"], urls: [] },
    });
    const records = buildIndicators([evil, again, clean]);
    const entry = records.find((r) => r.value === "chase-secure.co")!;

    expect(entry.reports).toBe(2);
    expect(entry.reportIds.map((r) => r.id).sort()).toEqual(["e1", "e3"]);
    expect(entry.lastSeen).toBeGreaterThan(entry.firstSeen);
  });
});

describe("topStrings", () => {  it("ranks values by frequency and skips blanks", () => {
    expect(topStrings(["b.co", "a.co", "b.co", "", undefined, "a.co", "b.co"], 2)).toEqual([
      { value: "b.co", count: 3 },
      { value: "a.co", count: 2 },
    ]);
  });
});

describe("scansToCsv", () => {
  it("renders a header plus one quoted row per scan", () => {
    const csv = scansToCsv([
      scan({ verdict: "Malicious", t: "2026-10-15T12:00:00.000Z", filename: 'chase,"alert".eml' }),
    ]);
    const lines = csv.split("\n");

    expect(lines[0]).toBe("id,time,filename,kind,verdict,score,mode");
    expect(lines[1]).toContain('"chase,""alert"".eml"');
    expect(lines[1]).toContain("Malicious");
  });
});

describe("relativeTime", () => {
  it("formats recent timestamps", () => {
    expect(relativeTime(new Date(NOW - 10 * 1000).toISOString(), NOW)).toBe("just now");
    expect(relativeTime(new Date(NOW - 5 * 60 * 1000).toISOString(), NOW)).toBe("5 min ago");
    expect(relativeTime(new Date(NOW - 2 * HOUR).toISOString(), NOW)).toBe("2 hrs ago");
    expect(relativeTime(new Date(NOW - 3 * DAY_MS).toISOString(), NOW)).toBe("3 days ago");
    expect(relativeTime("not-a-date", NOW)).toBe("unknown");
  });
});
