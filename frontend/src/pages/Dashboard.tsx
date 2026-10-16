import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Cell, Pie, PieChart, Tooltip } from "recharts";
import {
  ArrowDown, ArrowUp, ChevronDown, Crosshair, Gauge, MoreVertical, RefreshCw, ShieldAlert, SlidersHorizontal, TriangleAlert,
} from "lucide-react";

import { ScanDetailModal } from "@/components/scan-detail-modal";
import { ScanPanel } from "@/components/scan-panel";
import { FilterDropdown } from "@/components/filter-dropdown";
import { WorkspaceShell } from "@/components/workspace-shell";
import { fetchHistory } from "@/lib/api";
import {
  buildStats,
  buildTrend,
  relativeTime,
  severityDistribution,
  shortDate,
  verdictTone,
} from "@/lib/threat-stats";

const ROW_GRID = "grid grid-cols-[1fr_2fr_1.2fr_1fr_1.4fr_1.2fr_0.8fr]";

const TREND_RANGES = [
  { value: 1, label: "1 day" },
  { value: 3, label: "3 days" },
  { value: 7, label: "7 days" },
  { value: 30, label: "1 month" },
  { value: 90, label: "3 months" },
  { value: 365, label: "1 year" },
];

export function Dashboard() {
  const history = useQuery({ queryKey: ["history"], queryFn: fetchHistory, refetchInterval: 30_000 });

  const scans = history.data ?? [];

  const [trendDays, setTrendDays] = useState(7);
  const [viewId, setViewId] = useState<string | null>(null);

  const stats = buildStats(scans);
  const distribution = severityDistribution(scans);
  const trend = buildTrend(scans, trendDays);
  const rows = scans.slice(0, 5);

  const severityData = [
    { name: "Critical", value: distribution.critical, fill: "var(--destructive)" },
    { name: "High", value: distribution.high, fill: "var(--warning)" },
    { name: "Low", value: distribution.low, fill: "var(--success)" },
  ];

  const STATS = [
    { title: "Critical Threats", value: stats.critical, delta: stats.criticalDelta, note: "Active critical severity threats", icon: ShieldAlert },
    { title: "New IOCs", value: stats.iocs, delta: stats.iocsDelta, note: "Unique indicators on record", icon: Crosshair, hi: true },
    { title: "Suspicious Threats", value: stats.suspicious, delta: stats.suspiciousDelta, note: "Needs a human look", icon: TriangleAlert },
    { title: "Scans Analysed", value: stats.scans, delta: stats.scansDelta, note: "Verdicts in the report store", icon: Gauge },
  ];

  const refreshAction = (
    <button onClick={() => history.refetch()} className="flex cursor-pointer items-center gap-2 rounded-[3px] border border-border px-3 py-2 text-sm text-on-chrome">
      <RefreshCw size={16} className={`text-primary ${history.isFetching ? "animate-spin" : ""}`} /> Refresh Data
    </button>
  );

  return (
    <WorkspaceShell section="Dashboard" actions={refreshAction}>
      <div className="space-y-8 p-6">
          <section className="grid grid-cols-2 gap-5 xl:grid-cols-4">
            {STATS.map((s, i) => (
              <div key={i} className="kpi-card p-5 text-center">
                <span className="mx-auto grid h-10 w-10 place-items-center rounded-full border border-border bg-secondary"><s.icon size={16} /></span>
                <p className="mt-3">{s.title}</p>
                <p className={`mt-2 text-3xl ${s.hi ? "text-foreground" : "text-primary"}`}>{s.value}</p>
                <div className="mt-4 flex items-center justify-center gap-2 border-t border-border pt-4 text-xs">
                  <span className="flex items-center gap-0.5 rounded-full bg-secondary px-2 py-1">
                    {s.delta >= 0 ? <ArrowUp size={12} /> : <ArrowDown size={12} className="text-destructive" />}
                    {s.delta >= 0 ? "+" : "−"}{Math.abs(s.delta)}%
                  </span>
                  <span className="text-muted-foreground">{s.note}</span>
                </div>
              </div>
            ))}
          </section>

          <ScanPanel onScanned={() => history.refetch()} />

          <section className="grid gap-6 xl:grid-cols-[1.15fr_1fr]">
            <div>
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-2xl">Threat Trend by Severity</h2>
                <FilterDropdown
                  label="Trend range"
                  icon={SlidersHorizontal}
                  prefix="Last"
                  value={trendDays}
                  options={TREND_RANGES}
                  onChange={setTrendDays}
                  menuAlign="right"
                />
              </div>
              <div className="chart-bg grid-bg relative h-80 overflow-hidden rounded-[3px] border border-border">
                <svg viewBox="0 0 430 260" className="h-full w-full" preserveAspectRatio="none">
                  {trend.map((p, i) => {
                    const slot = 430 / trend.length;
                    const barWidth = Math.max(1, Math.min(34, slot * 0.55));
                    const x = i * slot + (slot - barWidth) / 2;
                    return (
                      <g key={i}>
                        <rect
                          x={x}
                          y={p.y}
                          width={barWidth}
                          height={Math.max(0, 230 - p.y)}
                          rx={Math.min(3, barWidth / 2)}
                          className="fill-primary"
                          opacity={0.85}
                        />
                        {p.label > 0 && trend.length <= 14 && (
                          <text x={x + barWidth / 2} y={Math.max(10, p.y - 10)} textAnchor="middle" className="fill-primary" fontSize={10}>
                            {p.label}
                          </text>
                        )}
                      </g>
                    );
                  })}
                </svg>
                <p className="absolute bottom-4 w-full text-center text-xs text-muted-foreground">
                  {scans.length === 0 ? "No verdicts in the last 7 days" : "Verdicts per day · agent scans in the sandbox"}
                </p>
              </div>
            </div>
            <div>
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-2xl">Severity Distribution</h2>
                <button className="cursor-pointer rounded-[3px] border border-primary bg-secondary p-2"><MoreVertical size={16} /></button>
              </div>
              <div className="chart-bg relative flex h-80 flex-col overflow-hidden rounded-[3px] border border-border px-4 pb-12 pt-4">
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
                      data={severityData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius="62%"
                      outerRadius="88%"
                      paddingAngle={3}
                      strokeWidth={0}
                    >
                      {severityData.map((entry) => (
                        <Cell key={entry.name} fill={entry.fill} />
                      ))}
                    </Pie>
                  </PieChart>
                  <div className="pointer-events-none absolute inset-0 grid place-items-center">
                    <div className="text-center">
                      <p className="text-3xl text-foreground">{scans.length}</p>
                      <p className="text-xs text-muted-foreground">threats</p>
                    </div>
                  </div>
                </div>
                <div className="mt-3 flex items-center justify-center gap-5 text-sm">
                  {severityData.map((s) => (
                    <span key={s.name} className="flex items-center gap-1.5">
                      <span
                        className="h-2.5 w-2.5 shrink-0 rounded-[2px]"
                        style={{ backgroundColor: s.fill }}
                      />
                      {s.name} {s.value}%
                    </span>
                  ))}
                </div>
                <p className="absolute bottom-5 w-full text-center text-sm">Current threats by severity level</p>
              </div>
            </div>
          </section>

          <section className="space-y-3">
            <div className={`${ROW_GRID} px-6 text-sm`}>
              <span>Severity</span><span>Title</span><span className="flex items-center gap-2">Type <ChevronDown size={14} /></span>
              <span>Date</span><span>Source</span><span>Detected</span><span className="flex items-center gap-2">Action <ChevronDown size={14} /></span>
            </div>
            {history.isPending && (
              <div className="row-panel px-6 py-5 text-sm text-muted-foreground">Loading recent verdicts…</div>
            )}
            {history.isError && (
              <div className="row-panel px-6 py-5 text-sm text-destructive">
                Could not load verdict history: {(history.error as Error).message}
              </div>
            )}
            {!history.isPending && !history.isError && rows.length === 0 && (
              <div className="row-panel px-6 py-5 text-sm text-muted-foreground">
                No scans yet — drop a file or paste a bank email above to get a verdict.
              </div>
            )}
            {rows.map((r) => (
              <div key={r.id} className={`row-panel ${ROW_GRID} items-center px-6 py-4 text-sm`}>
                <span className={verdictTone(r.verdict)}>{r.verdict}</span><span>{r.filename}</span>
                <span>{r.kind === "email" ? "Email threat" : "File"}</span><span>{shortDate(r.t)}</span>
                <span className="truncate">{r.mode ?? "—"}</span>
                <span className={`w-fit rounded-full bg-secondary px-4 py-2 ${r.verdict === "Verified" ? "text-success" : ""}`}>{relativeTime(r.t)}</span>
                <button
                  type="button"
                  onClick={() => setViewId(r.id)}
                  className="w-fit cursor-pointer text-left"
                >
                  View
                </button>
              </div>
            ))}
          </section>
      </div>

      <ScanDetailModal id={viewId} onClose={() => setViewId(null)} />
    </WorkspaceShell>
  );
}
