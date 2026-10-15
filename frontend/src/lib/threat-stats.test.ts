import { describe, expect, it } from "vitest";

import type { ScanSummary } from "./api";
import {
  DAY_MS,
  buildStats,
  buildTrend,
  relativeTime,
  severityDistribution,
  trendPolyline,
  uniqueIocs,
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

describe("relativeTime", () => {
  it("formats recent timestamps", () => {
    expect(relativeTime(new Date(NOW - 10 * 1000).toISOString(), NOW)).toBe("just now");
    expect(relativeTime(new Date(NOW - 5 * 60 * 1000).toISOString(), NOW)).toBe("5 min ago");
    expect(relativeTime(new Date(NOW - 2 * HOUR).toISOString(), NOW)).toBe("2 hrs ago");
    expect(relativeTime(new Date(NOW - 3 * DAY_MS).toISOString(), NOW)).toBe("3 days ago");
    expect(relativeTime("not-a-date", NOW)).toBe("unknown");
  });
});
