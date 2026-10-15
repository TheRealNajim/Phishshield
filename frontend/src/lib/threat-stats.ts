import type { ScanSummary, Verdict } from "./api";

export const HOUR_MS = 60 * 60 * 1000;
export const DAY_MS = 24 * HOUR_MS;

const at = (scan: ScanSummary) => Date.parse(scan.t);

/** Percent change between the last 24h and the 24h before it. Fresh activity with no baseline reads as +100%; no activity at all reads as 0%. */
function change24h(pick: (scans: ScanSummary[]) => number, scans: ScanSummary[], now: number) {
  return windowedChange(pick, scans, now, DAY_MS);
}

/**
 * Percent change of `pick` between the window (end - ms, end] and the
 * equal-length window immediately before it. Fresh activity with no baseline
 * reads as +100%; no activity at all reads as 0%.
 */
export function windowedChange(
  pick: (scans: ScanSummary[]) => number,
  scans: ScanSummary[],
  end: number,
  ms: number,
): number {
  const inWindow = (from: number, to: number) =>
    scans.filter((s) => {
      const t = at(s);
      return Number.isFinite(t) && t > from && t <= to;
    });
  const last = pick(inWindow(end - ms, end));
  const previous = pick(inWindow(end - 2 * ms, end - ms));
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

export interface ActivityBucket {
  /** Bucket start as epoch ms. */
  start: number;
  /** Short axis label ("Mon", "13:00", "12 May"). */
  label: string;
  scans: number;
  /** Malicious + Suspicious scans in the bucket. */
  threats: number;
}

/**
 * Scan volume and threat counts bucketed over the `days` ending at `end`:
 * hourly buckets for a single day, daily up to 45 days, weekly beyond that.
 */
export function buildActivity(scans: ScanSummary[], end: number, days: number): ActivityBucket[] {
  const span = Math.max(1, Math.round(days));
  if (span <= 1) return bucketize(scans, end, 24, HOUR_MS, hourlyLabel);
  if (span <= 45) return bucketize(scans, end, span, DAY_MS, dailyLabel);
  return bucketize(scans, end, Math.ceil(span / 7), 7 * DAY_MS, weeklyLabel);
}

function bucketize(
  scans: ScanSummary[],
  end: number,
  count: number,
  size: number,
  label: (start: number) => string,
): ActivityBucket[] {
  return Array.from({ length: count }, (_, i) => {
    const start = end - (count - i) * size;
    let bucketScans = 0;
    let threats = 0;
    for (const s of scans) {
      const t = at(s);
      if (!Number.isFinite(t) || t <= start || t > start + size) continue;
      bucketScans += 1;
      if (s.verdict === "Malicious" || s.verdict === "Suspicious") threats += 1;
    }
    return { start, label: label(start), scans: bucketScans, threats };
  });
}

function hourlyLabel(start: number) {
  return `${String(new Date(start).getHours()).padStart(2, "0")}:00`;
}

function dailyLabel(start: number) {
  return new Date(start).toLocaleDateString("en-US", { weekday: "short" });
}

function weeklyLabel(start: number) {
  return new Date(start).toLocaleDateString("en-GB", { day: "numeric", month: "short" });
}

export interface ThreatCategory {
  name: string;
  count: number;
}

const CATEGORY_RULES: { name: string; test: (text: string, scan: ScanSummary) => boolean }[] = [
  { name: "Brand impersonation", test: (text) => /impersonat|imitat|spoof|brand/i.test(text) },
  {
    name: "Suspicious links",
    test: (text, s) => (s.iocs?.urls?.length ?? 0) > 0 || /link|url|href/i.test(text),
  },
  {
    name: "Credential theft",
    test: (text) => /credential|password|\bbvn\b|\bnin\b|\botp\b|\bpin\b|login|passcode/i.test(text),
  },
  {
    name: "Lookalike domains",
    test: (text, s) => (s.iocs?.domains?.length ?? 0) > 0 || /lookalike/i.test(text),
  },
];

/** Recurring threat patterns. Categories may overlap within one scan. */
export function threatCategories(scans: ScanSummary[]): ThreatCategory[] {
  return CATEGORY_RULES.map(({ name, test }) => ({
    name,
    count: scans.filter((s) => test((s.reasons ?? []).join(" "), s)).length,
  })).sort((a, b) => b.count - a.count);
}

/** First matching threat pattern, or a fallback. Verified scans carry no finding. */
export function primaryCategory(scan: ScanSummary): string {
  if (scan.verdict === "Verified") return "No significant indicators";
  const text = (scan.reasons ?? []).join(" ");
  const match = CATEGORY_RULES.find(({ test }) => test(text, scan));
  return match ? match.name : "Unclassified";
}

export type IndicatorType = "Domain" | "URL" | "IP address" | "SHA-256";
export type IndicatorAssessment = Verdict | "Unassessed";

export interface IndicatorRecord {
  /** Original extracted value. URLs render as text only — never auto-opened. */
  value: string;
  type: IndicatorType;
  /**
   * Verdict evidence for THIS artifact, not its scans: the worst verdict among
   * linked scans whose reasons actually mention it. Otherwise Unassessed —
   * appearing in a report alone proves nothing more.
   */
  assessment: IndicatorAssessment;
  reports: number;
  firstSeen: number;
  lastSeen: number;
  /** Linked reasons that mention this artifact, deduped. */
  evidence: string[];
  reportIds: LinkedReport[];
}

function isIpHost(host: string) {
  const bare = host.replace(/^\[|\]$/g, "");
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(bare) || bare.includes(":");
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function mentions(reason: string, value: string, host: string | null) {
  const text = reason.toLowerCase();
  return text.includes(value.toLowerCase()) || (host !== null && text.includes(host));
}

/**
 * Technical artifacts extracted from stored scan records, deduped by
 * normalized value: indicator domains, full URLs, IP hosts found in URLs or
 * domain fields, and file hashes.
 */
export function buildIndicators(scans: ScanSummary[]): IndicatorRecord[] {
  const groups = new Map<string, { value: string; type: IndicatorType; scans: ScanSummary[] }>();

  function add(key: string, value: string, type: IndicatorType, scan: ScanSummary) {
    if (!key) return;
    const entry = groups.get(key) ?? { value, type, scans: [] };
    entry.scans.push(scan);
    groups.set(key, entry);
  }

  for (const scan of scans) {
    for (const d of scan.iocs?.domains ?? []) {
      const host = d.toLowerCase();
      add(host, d, isIpHost(host) ? "IP address" : "Domain", scan);
    }
    for (const u of scan.iocs?.urls ?? []) {
      add(u, u, "URL", scan);
      const host = hostOf(u);
      if (host && isIpHost(host)) add(host, host, "IP address", scan);
    }
    const shaRaw = scan.iocs?.sha256;
    if (shaRaw) add(shaRaw.toLowerCase(), shaRaw, "SHA-256", scan);
  }

  const rank: Record<IndicatorAssessment, number> = {
    Malicious: 3,
    Suspicious: 2,
    Verified: 1,
    Unassessed: 0,
  };

  const records: IndicatorRecord[] = [];
  for (const { value, type, scans: linked } of groups.values()) {
    const host =
      type === "URL" ? hostOf(value) : type === "SHA-256" ? null : value.toLowerCase();
    let assessment: IndicatorAssessment = "Unassessed";
    const evidence: string[] = [];
    for (const s of linked) {
      const naming = (s.reasons ?? []).filter((reason) => mentions(reason, value, host));
      if (naming.length > 0 && rank[s.verdict] > rank[assessment]) assessment = s.verdict;
      for (const reason of naming) {
        if (!evidence.includes(reason)) evidence.push(reason);
      }
    }
    const times = linked.map((s) => Date.parse(s.t)).filter((t) => Number.isFinite(t));
    records.push({
      value,
      type,
      assessment,
      reports: linked.length,
      firstSeen: times.length > 0 ? Math.min(...times) : 0,
      lastSeen: times.length > 0 ? Math.max(...times) : 0,
      evidence,
      reportIds: [...linked]
        .sort((a, b) => Date.parse(b.t) - Date.parse(a.t))
        .map((s) => ({ id: s.id, filename: s.filename, verdict: s.verdict, t: s.t, score: s.score ?? 0 })),
    });
  }

  return records.sort(
    (a, b) =>
      rank[b.assessment] - rank[a.assessment] || b.reports - a.reports || b.lastSeen - a.lastSeen,
  );
}

export type SourceType = "Lookalike domain" | "Link destination" | "Observed domain";

export interface LinkedReport {
  id: string;
  filename: string;
  verdict: Verdict;
  t: string;
  score: number;
}

export interface SourceRecord {
  /** Lowercased host: a domain from indicators or a link hostname. */
  source: string;
  type: SourceType;
  /** Domain the evidence says is being imitated, if the scanner named one. */
  brand: string | null;
  /** Worst verdict across linked scans: Malicious > Suspicious > Verified. */
  verdict: Verdict;
  scans: number;
  firstSeen: number;
  lastSeen: number;
  /** Highest risk score across linked scans. */
  score: number;
  /** Linked reasons that mention this source, deduped. */
  evidence: string[];
  reports: LinkedReport[];
}

const VERDICT_RANK: Record<Verdict, number> = { Verified: 1, Suspicious: 2, Malicious: 3 };

function urlHosts(urls: string[]): string[] {
  const hosts: string[] = [];
  for (const u of urls ?? []) {
    try {
      hosts.push(new URL(u).hostname.toLowerCase());
    } catch {
      /* ignore unparseable values */
    }
  }
  return hosts;
}

const IMITATED_PATTERN =
  /(?:imitates?|impersonat\w*|spoof\w*)\s+([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)/i;

/** Domain the evidence says is being imitated, if the scanner named one. */
export function brandInReasons(reasons: string[]): string | null {
  for (const reason of reasons) {
    const match = IMITATED_PATTERN.exec(reason);
    if (match?.[1]) return match[1].toLowerCase();
  }
  return null;
}

function extractBrand(reasons: string[]): string | null {
  return brandInReasons(reasons);
}

/**
 * Observed sources aggregated from stored scan records: indicator domains
 * plus link hostnames, grouped case-insensitively. A source is only ever as
 * bad as its worst linked scan verdict — appearing in an email alone proves
 * nothing more.
 */
export function buildSources(scans: ScanSummary[]): SourceRecord[] {
  const groups = new Map<
    string,
    { scans: ScanSummary[]; fromUrl: boolean; lookalike: boolean }
  >();

  for (const scan of scans) {
    const domains = (scan.iocs?.domains ?? []).map((d) => d.toLowerCase());
    const hosts = urlHosts(scan.iocs?.urls);
    const text = (scan.reasons ?? []).join(" ");
    const mentionsLookalike = /lookalike|imitat|spoof/i.test(text);

    const seen = new Set<string>();
    for (const d of domains) {
      if (!d || seen.has(d)) continue;
      seen.add(d);
      const entry = groups.get(d) ?? { scans: [], fromUrl: false, lookalike: false };
      entry.scans.push(scan);
      if (mentionsLookalike && text.toLowerCase().includes(d)) entry.lookalike = true;
      groups.set(d, entry);
    }
    for (const h of hosts) {
      if (!h || seen.has(h)) continue;
      seen.add(h);
      const entry = groups.get(h) ?? { scans: [], fromUrl: false, lookalike: false };
      entry.scans.push(scan);
      entry.fromUrl = true;
      if (mentionsLookalike && text.toLowerCase().includes(h)) entry.lookalike = true;
      groups.set(h, entry);
    }
  }

  const records: SourceRecord[] = [];
  for (const [source, entry] of groups) {
    const linked = entry.scans;
    const verdict = linked.reduce<Verdict>(
      (worst, s) => (VERDICT_RANK[s.verdict] > VERDICT_RANK[worst] ? s.verdict : worst),
      "Verified",
    );
    const times = linked
      .map((s) => Date.parse(s.t))
      .filter((t) => Number.isFinite(t));
    const evidence = [
      ...new Set(
        linked
          .flatMap((s) => s.reasons ?? [])
          .filter((reason) => reason.toLowerCase().includes(source)),
      ),
    ];
    const brand = extractBrand(linked.flatMap((s) => s.reasons ?? []));
    records.push({
      source,
      type: entry.lookalike ? "Lookalike domain" : entry.fromUrl ? "Link destination" : "Observed domain",
      brand,
      verdict,
      scans: linked.length,
      firstSeen: times.length > 0 ? Math.min(...times) : 0,
      lastSeen: times.length > 0 ? Math.max(...times) : 0,
      score: Math.max(0, ...linked.map((s) => s.score ?? 0)),
      evidence,
      reports: [...linked]
        .sort((a, b) => Date.parse(b.t) - Date.parse(a.t))
        .map((s) => ({ id: s.id, filename: s.filename, verdict: s.verdict, t: s.t, score: s.score ?? 0 })),
    });
  }

  return records.sort(
    (a, b) =>
      VERDICT_RANK[b.verdict] - VERDICT_RANK[a.verdict] ||
      b.scans - a.scans ||
      b.lastSeen - a.lastSeen,
  );
}

/** Most frequent strings with counts, highest first. */
export function topStrings(
  values: (string | undefined)[],
  limit = 5,
): { value: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const v of values) {
    if (!v) continue;
    counts.set(v, (counts.get(v) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
    .slice(0, limit);
}

function csvCell(value: unknown) {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/** Filtered scan records as CSV for the analytics export. */
export function scansToCsv(rows: ScanSummary[]): string {
  const header = ["id", "time", "filename", "kind", "verdict", "score", "mode"];
  const lines = rows.map((r) =>
    [r.id, r.t, r.filename, r.kind, r.verdict, r.score, r.mode ?? ""].map(csvCell).join(","),
  );
  return [header.join(","), ...lines].join("\n");
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
