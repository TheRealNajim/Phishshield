import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Cell, Pie, PieChart, Tooltip } from "recharts";
import { ArrowDown, ArrowUp, Download, RefreshCw } from "lucide-react";

import { FilterDropdown } from "@/components/filter-dropdown";

import { ScanDetailModal } from "@/components/scan-detail-modal";
import { WorkspaceShell } from "@/components/workspace-shell";
import { fetchHistory, type Verdict } from "@/lib/api";
import {
  DAY_MS,
  buildActivity,
  countByVerdict,
  relativeTime,
  scansToCsv,
  threatCategories,
  topStrings,
  verdictTone,
  windowedChange,
} from "@/lib/threat-stats";
import { navigate } from "@/lib/route";

type RangePreset = "24h" | "7d" | "30d" | "custom";
const RANGE_PRESETS: { id: RangePreset; label: string }[] = [
  { id: "24h", label: "24 hours" },
  { id: "7d", label: "7 days" },
  { id: "30d", label: "30 days" },
  { id: "custom", label: "Custom" },
];

const KIND_OPTIONS = [
  { value: "all", label: "All types" },
  { value: "email", label: "Email" },
  { value: "file", label: "File" },
] as const;

const VERDICT_OPTIONS = [
  { value: "all", label: "All verdicts" },
  { value: "Verified", label: "Verified" },
  { value: "Suspicious", label: "Suspicious" },
  { value: "Malicious", label: "Malicious" },
] as const;

export function Analytics() {
  const history = useQuery({ queryKey: ["history"], queryFn: fetchHistory, refetchInterval: 30_000 });
  const scans = history.data ?? [];
  const [now] = useState(() => Date.now());

  const [preset, setPreset] = useState<RangePreset>("7d");
  const [customStart, setCustomStart] = useState("");
  const [customEnd, setCustomEnd] = useState("");
  const [kind, setKind] = useState<"all" | "email" | "file">("all");
  const [verdict, setVerdict] = useState<"all" | Verdict>("all");
  const [viewId, setViewId] = useState<string | null>(null);

  const range = useMemo(() => {
    if (preset === "24h") return { start: now - DAY_MS, end: now, days: 1 };
    if (preset === "30d") return { start: now - 30 * DAY_MS, end: now, days: 30 };
    if (preset === "custom") {
      const s = Date.parse(customStart);
      const e = Date.parse(customEnd);
      if (Number.isFinite(s) && Number.isFinite(e) && e >= s) {
        const end = Math.min(e + DAY_MS, now);
        return { start: s, end, days: Math.max(1, Math.ceil((end - s) / DAY_MS)) };
      }
    }
    return { start: now - 7 * DAY_MS, end: now, days: 7 };
  }, [preset, customStart, customEnd, now]);

  const scoped = useMemo(
    () =>
      scans.filter(
        (s) =>
          (kind === "all" ? true : s.kind === kind) &&
          (verdict === "all" ? true : s.verdict === verdict),
      ),
    [scans, kind, verdict],
  );

  const filtered = useMemo(() => {
    const inRange = scoped.filter((s) => {
      const t = Date.parse(s.t);
      return Number.isFinite(t) && t >= range.start && t <= range.end;
    });
    return [...inRange].sort((a, b) => Date.parse(b.t) - Date.parse(a.t));
  }, [scoped, range]);

  const counts = countByVerdict(filtered);
  const total = filtered.length;
  const share = (n: number) => (total === 0 ? 0 : Math.round((n / total) * 100));
  const span = Math.max(range.end - range.start, 60 * 60 * 1000);
  const totalDelta = windowedChange((s) => s.length, scoped, range.end, span);

  const activity = useMemo(
    () => buildActivity(filtered, range.end, range.days),
    [filtered, range],
  );
  const maxVolume = Math.max(1, ...activity.map((b) => b.scans));
  const barY = (v: number) => 230 - (v / maxVolume) * 180;

  const distData = [
    { name: "Malicious", count: counts.Malicious, share: share(counts.Malicious), fill: "var(--destructive)" },
    { name: "Suspicious", count: counts.Suspicious, share: share(counts.Suspicious), fill: "var(--warning)" },
    { name: "Verified", count: counts.Verified, share: share(counts.Verified), fill: "var(--success)" },
  ];

  const categories = useMemo(() => threatCategories(filtered), [filtered]);
  const topCategory = Math.max(1, ...categories.map((c) => c.count));

  const topDomains = useMemo(
    () => topStrings(filtered.flatMap((s) => s.iocs.domains)),
    [filtered],
  );
  const topUrls = useMemo(() => topStrings(filtered.flatMap((s) => s.iocs.urls)), [filtered]);

  const recent = filtered.slice(0, 5);

  function exportCsv() {
    const blob = new Blob([scansToCsv(filtered)], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `phishshield-analytics-${preset}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  const KPIS = [
    {
      title: "Total scans",
      value: total,
      sub: (
        <>
          {totalDelta >= 0 ? <ArrowUp size={12} /> : <ArrowDown size={12} className="text-destructive" />}
          {totalDelta >= 0 ? "+" : "−"}{Math.abs(totalDelta)}% vs previous period
        </>
      ),
      to: "#/reports",
    },
    {
      title: "Threats detected",
      value: counts.Malicious,
      sub: <>{share(counts.Malicious)}% of scans</>,
      to: "#/threats?verdict=Malicious",
    },
    {
      title: "Suspicious",
      value: counts.Suspicious,
      sub: <>{share(counts.Suspicious)}% of scans</>,
      to: "#/threats?verdict=Suspicious",
    },
    {
      title: "Low risk / verified",
      value: counts.Verified,
      sub: <>{share(counts.Verified)}% of scans</>,
      to: "#/reports?verdict=Verified",
    },
  ];

  return (
    <WorkspaceShell
      section="Analytics"
      actions={
        <button onClick={() => history.refetch()} className="flex cursor-pointer items-center gap-2 rounded-[3px] border border-border px-3 py-2 text-sm text-on-chrome">
          <RefreshCw size={16} className={`text-primary ${history.isFetching ? "animate-spin" : ""}`} /> Refresh Data
        </button>
      }
    >
      <div className="space-y-8 p-6">
        <div className="panel flex flex-wrap items-center gap-3 p-4">
          <div className="flex w-fit gap-1 rounded-[3px] border border-border bg-secondary p-0.5 text-sm">
            {RANGE_PRESETS.map((r) => (
              <button
                key={r.id}
                type="button"
                onClick={() => setPreset(r.id)}
                aria-pressed={preset === r.id}
                className={`cursor-pointer rounded-[3px] px-4 py-2 ${preset === r.id ? "bg-card text-foreground" : "text-muted-foreground"}`}
              >
                {r.label}
              </button>
            ))}
          </div>
          {preset === "custom" && (
            <div className="flex items-center gap-2 text-sm">
              <input
                type="date"
                aria-label="Custom range start"
                value={customStart}
                onChange={(e) => setCustomStart(e.target.value)}
                className="cursor-pointer rounded-[3px] border border-border bg-secondary px-4 py-2.5 text-foreground"
              />
              <span className="text-muted-foreground">→</span>
              <input
                type="date"
                aria-label="Custom range end"
                value={customEnd}
                onChange={(e) => setCustomEnd(e.target.value)}
                className="cursor-pointer rounded-[3px] border border-border bg-secondary px-4 py-2.5 text-foreground"
              />
            </div>
          )}
          <FilterDropdown label="Scan type" value={kind} options={KIND_OPTIONS} onChange={setKind} />
          <FilterDropdown label="Verdict" value={verdict} options={VERDICT_OPTIONS} onChange={setVerdict} />
          <button
            type="button"
            onClick={exportCsv}
            disabled={filtered.length === 0}
            className="ml-auto flex cursor-pointer items-center gap-2 rounded-[3px] border border-border px-4 py-2.5 text-sm disabled:opacity-50"
          >
            <Download size={16} /> Export CSV
          </button>
        </div>

        <section className="grid grid-cols-2 gap-5 xl:grid-cols-4">
          {KPIS.map((k) => (
            <button
              key={k.title}
              type="button"
              onClick={() => navigate(k.to)}
              className="kpi-card cursor-pointer p-5 text-center"
            >
              <p className="mt-3">{k.title}</p>
              <p className="mt-2 text-3xl text-primary">{k.value}</p>
              <div className="mt-4 flex items-center justify-center gap-2 border-t border-border pt-4 text-xs">
                <span className="flex items-center gap-0.5 rounded-full bg-secondary px-2 py-1">
                  {k.sub}
                </span>
              </div>
            </button>
          ))}
        </section>

        <section className="grid gap-6 xl:grid-cols-[1.15fr_1fr]">
          <div>
            <div className="mb-4">
              <h2 className="text-2xl">Threat activity</h2>
              <p className="text-sm text-muted-foreground">Scan volume and threat detections over time</p>
            </div>
            <div className="chart-bg grid-bg relative h-80 overflow-hidden rounded-[3px] border border-border">
              <div className="absolute left-4 top-3 flex items-center gap-4 text-xs text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-[2px] bg-primary" /> Scans
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-[2px] bg-destructive" /> Threats detected
                </span>
              </div>
              <svg viewBox="0 0 430 260" className="h-full w-full" preserveAspectRatio="none">
                {activity.map((b, i) => {
                  const slot = 430 / activity.length;
                  const barWidth = Math.max(1, slot * 0.26);
                  const x1 = i * slot + slot / 2 - barWidth - 1;
                  const x2 = i * slot + slot / 2 + 1;
                  return (
                    <g key={b.start}>
                      <rect x={x1} y={barY(b.scans)} width={barWidth} height={Math.max(0, 230 - barY(b.scans))} rx={Math.min(3, barWidth / 2)} className="fill-primary" opacity={0.55}>
                        <title>{`${b.label}: ${b.scans} scans, ${b.threats} threats`}</title>
                      </rect>
                      <rect x={x2} y={barY(b.threats)} width={barWidth} height={Math.max(0, 230 - barY(b.threats))} rx={Math.min(3, barWidth / 2)} className="fill-destructive" opacity={0.9}>
                        <title>{`${b.label}: ${b.scans} scans, ${b.threats} threats`}</title>
                      </rect>
                      {activity.length <= 14 && (
                        <text x={i * slot + slot / 2} y={248} textAnchor="middle" className="fill-muted-foreground" fontSize={10}>
                          {b.label}
                        </text>
                      )}
                    </g>
                  );
                })}
              </svg>
              <p className="absolute bottom-4 w-full text-center text-xs text-muted-foreground">
                {filtered.length === 0 ? "No scans in this period" : "Daily scan volume and threat detections"}
              </p>
            </div>
          </div>
          <div>
            <div className="mb-4">
              <h2 className="text-2xl">Verdict distribution</h2>
              <p className="text-sm text-muted-foreground">Scan verdicts in this period</p>
            </div>
            <div className="chart-bg relative flex h-80 flex-col overflow-hidden rounded-[3px] border border-border px-4 pb-4 pt-4">
              <div className="relative mx-auto h-52 w-52">
                <PieChart width={208} height={208}>
                  <Tooltip
                    formatter={(value) => `${value}%`}
                    contentStyle={{
                      background: "var(--popover)",
                      border: "1px solid var(--border)",
                      borderRadius: 3,
                    }}
                    itemStyle={{ color: "var(--foreground)" }}
                  />
                  <Pie
                    data={distData}
                    dataKey="share"
                    nameKey="name"
                    innerRadius="62%"
                    outerRadius="88%"
                    paddingAngle={3}
                    strokeWidth={0}
                  >
                    {distData.map((entry) => (
                      <Cell key={entry.name} fill={entry.fill} />
                    ))}
                  </Pie>
                </PieChart>
                <div className="pointer-events-none absolute inset-0 grid place-items-center">
                  <div className="text-center">
                    <p className="text-3xl text-foreground">{total}</p>
                    <p className="text-xs text-muted-foreground">scans</p>
                  </div>
                </div>
              </div>
              <div className="mt-3 space-y-1.5 text-sm">
                {distData.map((d) => (
                  <div key={d.name} className="flex items-center gap-2">
                    <span className="h-2.5 w-2.5 shrink-0 rounded-[2px]" style={{ backgroundColor: d.fill }} />
                    <span>{d.name}</span>
                    <span className="ml-auto text-muted-foreground">{d.count} · {d.share}%</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section className="grid gap-6 xl:grid-cols-2">
          <div>
            <div className="mb-4">
              <h2 className="text-2xl">Top threat categories</h2>
              <p className="text-sm text-muted-foreground">Based on detected indicators</p>
            </div>
            <div className="panel space-y-4 p-6">
              {categories.every((c) => c.count === 0) ? (
                <p className="text-sm text-muted-foreground">No threat patterns in this period.</p>
              ) : (
                categories.map((c) => (
                  <div key={c.name}>
                    <div className="flex items-center justify-between text-sm">
                      <span>{c.name}</span>
                      <span className="text-muted-foreground">{c.count}</span>
                    </div>
                    <div className="mt-1.5 h-2 w-full overflow-hidden rounded-[3px] bg-secondary">
                      <div
                        className="h-full bg-primary transition-all duration-300"
                        style={{ width: `${(c.count / topCategory) * 100}%` }}
                      />
                    </div>
                  </div>
                ))
              )}
              <p className="text-xs text-muted-foreground">Categories may overlap within one scan.</p>
            </div>
          </div>
          <div>
            <div className="mb-4">
              <h2 className="text-2xl">Detection insights</h2>
              <p className="text-sm text-muted-foreground">Most frequent domains and indicators</p>
            </div>
            <div className="panel space-y-6 p-6">
              <div>
                <p className="text-sm text-muted-foreground">Top domains</p>
                {topDomains.length === 0 ? (
                  <p className="mt-2 text-sm text-muted-foreground">No indicators in this period.</p>
                ) : (
                  <ul className="mt-2 space-y-1.5 text-sm">
                    {topDomains.map((d) => (
                      <li key={d.value} className="flex items-center gap-2">
                        <span className="truncate font-mono text-xs">{d.value}</span>
                        <span className="ml-auto rounded-full bg-secondary px-2 py-0.5 text-xs">{d.count}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Top URLs</p>
                {topUrls.length === 0 ? (
                  <p className="mt-2 text-sm text-muted-foreground">No indicators in this period.</p>
                ) : (
                  <ul className="mt-2 space-y-1.5 text-sm">
                    {topUrls.map((u) => (
                      <li key={u.value} className="flex items-center gap-2">
                        <span className="truncate font-mono text-xs">{u.value}</span>
                        <span className="ml-auto shrink-0 rounded-full bg-secondary px-2 py-0.5 text-xs">{u.count}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </div>
        </section>

        <section className="space-y-3">
          <div className="mb-4">
            <h2 className="text-2xl">Recent security activity</h2>
          </div>
          {history.isPending && (
            <div className="row-panel px-6 py-5 text-sm text-muted-foreground">Loading recent activity…</div>
          )}
          {history.isError && (
            <div className="row-panel px-6 py-5 text-sm text-destructive">
              Could not load activity: {(history.error as Error).message}
            </div>
          )}
          {!history.isPending && !history.isError && recent.length === 0 && (
            <div className="row-panel px-6 py-5 text-sm text-muted-foreground">
              No scans in this period.
            </div>
          )}
          {recent.map((r) => (
            <button
              key={r.id}
              type="button"
              onClick={() => setViewId(r.id)}
              className="row-panel flex w-full cursor-pointer flex-wrap items-center gap-x-4 gap-y-1 px-6 py-4 text-left text-sm"
            >
              <span className={verdictTone(r.verdict)}>{r.verdict}</span>
              <span className="min-w-0 flex-1 truncate">{r.filename}</span>
              <span className="text-xs text-muted-foreground">Risk score {r.score}</span>
              <span className="text-xs text-muted-foreground">{relativeTime(r.t)}</span>
              <span className="w-fit">View</span>
            </button>
          ))}
        </section>
      </div>

      <ScanDetailModal id={viewId} onClose={() => setViewId(null)} />
    </WorkspaceShell>
  );
}
