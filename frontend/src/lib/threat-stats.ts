import type { ScanSummary, Verdict } from "./api";

export const HOUR_MS = 60 * 60 * 1000;
export const DAY_MS = 24 * HOUR_MS;

const at = (scan: ScanSummary) => Date.parse(scan.t);

function withinLast(scans: ScanSummary[], ms: number, now: number) {
  return scans.filter((s) => {
    const t = at(s);
    return Number.isFinite(t) && now - t <= ms;
  });
}

/** Percent change between the last 24h and the 24h before it. Fresh activity with no baseline reads as +100%; no activity at all reads as 0%. */
function change24h(pick: (scans: ScanSummary[]) => number, scans: ScanSummary[], now: number) {
  const last = pick(withinLast(scans, DAY_MS, now));
  const previous = pick(
    scans.filter((s) => {
      const t = at(s);
      return Number.isFinite(t) && now - t > DAY_MS && now - t <= 2 * DAY_MS;
    }),
  );
  if (previous === 0) return last === 0 ? 0 : 100;
  return Math.round(((last - previous) / previous) * 100);
}

export function countByVerdict(scans: ScanSummary[]): Record<Verdict, number> {
  const counts: Record<Verdict, number> = { Verified: 0, Suspicious: 0, Malicious: 0 };
  for (const s of scans) {
    if (s.verdict in counts) counts[s.verdict] += 1;
  }
  return counts;
}

export function uniqueIocs(scans: ScanSummary[]): string[] {
  const set = new Set<string>();
  for (const s of scans) {
    if (s.iocs?.sha256) set.add(s.iocs.sha256);
    for (const d of s.iocs?.domains ?? []) set.add(d);
    for (const u of s.iocs?.urls ?? []) set.add(u);
  }
  return [...set];
}

export interface ThreatStats {
  critical: number;
  criticalDelta: number;
  iocs: number;
  iocsDelta: number;
  suspicious: number;
  suspiciousDelta: number;
  scans: number;
  scansDelta: number;
}

const severe = (scans: ScanSummary[]) => countByVerdict(scans).Malicious;
const suspiciousCount = (scans: ScanSummary[]) => countByVerdict(scans).Suspicious;
const iocCount = (scans: ScanSummary[]) => uniqueIocs(scans).length;

export function buildStats(scans: ScanSummary[], now = Date.now()): ThreatStats {
  return {
    critical: severe(scans),
    criticalDelta: change24h(severe, scans, now),
    iocs: iocCount(scans),
    iocsDelta: change24h(iocCount, scans, now),
    suspicious: suspiciousCount(scans),
    suspiciousDelta: change24h(suspiciousCount, scans, now),
    scans: scans.length,
    scansDelta: change24h((s) => s.length, scans, now),
  };
}

/** Share of each severity as whole percentages that add up to 100 (largest remainder wins). */
export function severityDistribution(scans: ScanSummary[]) {
  const counts = countByVerdict(scans);
  const total = scans.length;
  if (total === 0) return { critical: 0, high: 0, low: 0 };

  const raw = [
    { key: "critical" as const, value: (counts.Malicious / total) * 100 },
    { key: "high" as const, value: (counts.Suspicious / total) * 100 },
    { key: "low" as const, value: (counts.Verified / total) * 100 },
  ];

  const out = { critical: 0, high: 0, low: 0 };
  let assigned = 0;
  for (const { key, value } of raw) {
    out[key] = Math.floor(value);
    assigned += out[key];
  }
  const remainder = 100 - assigned;
  const byFraction = [...raw].sort((a, b) => (b.value % 1) - (a.value % 1));
  for (let i = 0; i < remainder; i++) {
    const entry = byFraction[i % byFraction.length]!;
    out[entry.key] += 1;
  }
  return out;
}

export interface TrendPoint {
  x: number;
  y: number;
  label: number;
}

const CHART = { width: 430, height: 260, base: 230, amplitude: 180 };

/** Daily scan counts for the last `days` days, mapped into the chart's viewBox. */
export function buildTrend(scans: ScanSummary[], days = 7, now = Date.now()): TrendPoint[] {
  const buckets = Array.from({ length: days }, () => 0);
  const startOfToday = new Date(now);
  startOfToday.setHours(0, 0, 0, 0);

  for (const s of scans) {
    const t = at(s);
    if (!Number.isFinite(t)) continue;
    // Bucket by calendar day: 0 = today (rightmost), counting backwards.
    const day = new Date(t);
    day.setHours(0, 0, 0, 0);
    // Rounded so DST-shifted 23h/25h days still land on the intended day.
    const dayIndex = Math.round((startOfToday.getTime() - day.getTime()) / DAY_MS);
    if (dayIndex >= 0 && dayIndex < days) {
      const bucket = days - 1 - dayIndex;
      buckets[bucket] = (buckets[bucket] ?? 0) + 1;
    }
  }

  const max = Math.max(...buckets, 0);
  const step = days > 1 ? CHART.width / (days - 1) : 0;

  return buckets.map((count, i) => ({
    x: Math.round(i * step),
    y: max === 0 ? CHART.base : Math.round(CHART.base - (count / max) * CHART.amplitude),
    label: count,
  }));
}

export function trendPolyline(points: TrendPoint[]) {
  return points.map((p) => `${p.x},${p.y}`).join(" ");
}

export function relativeTime(iso: string, now = Date.now()) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "unknown";
  const diff = Math.max(0, now - t);
  if (diff < 60 * 1000) return "just now";
  if (diff < HOUR_MS) return `${Math.round(diff / (60 * 1000))} min ago`;
  if (diff < DAY_MS) return `${Math.round(diff / HOUR_MS)} hrs ago`;
  return `${Math.round(diff / DAY_MS)} days ago`;
}

export function shortDate(iso: string) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "—";
  return new Date(t).toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
}

export function verdictTone(verdict: Verdict) {
  if (verdict === "Malicious") return "text-destructive";
  if (verdict === "Suspicious") return "text-warning";
  return "text-success";
}
