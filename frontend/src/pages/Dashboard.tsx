import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  LayoutGrid, BarChart3, Bug, Users, FileText, Gauge, TriangleAlert, Bot, Settings, Network,
  Home, ChevronRight, ChevronDown, Search, Moon, Sun, RefreshCw, ShieldAlert, Crosshair, ArrowUp, ArrowDown, MoreVertical, User,
} from "lucide-react";
import avatar from "@/assets/avatar.jpg";

import { ScanPanel } from "@/components/scan-panel";
import { fetchBilling, fetchHistory, reportUrl } from "@/lib/api";
import {
  buildStats,
  buildTrend,
  relativeTime,
  severityDistribution,
  shortDate,
  trendPolyline,
  verdictTone,
} from "@/lib/threat-stats";

type NavItem = { label: string; icon?: typeof LayoutGrid; heading?: boolean };
const NAV: NavItem[] = [
  { label: "Dashboard", icon: LayoutGrid },
  { label: "Analytics", icon: BarChart3 },
  { label: "Threats Intelligence", heading: true },
  { label: "Threats", icon: Bug },
  { label: "Sources", icon: Users },
  { label: "Reports", icon: FileText },
  { label: "Indicators", icon: Gauge },
  { label: "Operations", heading: true },
  { label: "Alerts", icon: TriangleAlert },
  { label: "SOCCo-Pilot", icon: Bot },
  { label: "Administration", heading: true },
  { label: "Setting", icon: Settings },
  { label: "Company Directory", icon: Network },
];

const ROW_GRID = "grid grid-cols-[1fr_2fr_1.2fr_1fr_1.4fr_1.2fr_0.8fr]";

export function Dashboard() {
  const history = useQuery({ queryKey: ["history"], queryFn: fetchHistory, refetchInterval: 30_000 });
  const billing = useQuery({ queryKey: ["billing"], queryFn: fetchBilling, staleTime: 5 * 60_000 });

  const scans = history.data ?? [];
  const [dark, setDark] = useState(
    () => typeof document !== "undefined" && document.documentElement.classList.contains("dark"),
  );

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);
  const stats = buildStats(scans);
  const distribution = severityDistribution(scans);
  const trend = buildTrend(scans);
  const guides = trend.slice(Math.max(0, trend.length - 6));
  const labels = trend.filter((p) => p.label > 0);
  const rows = scans.slice(0, 5);

  const STATS = [
    { title: "Critical Threats", value: stats.critical, delta: stats.criticalDelta, note: "Active critical severity threats", icon: ShieldAlert },
    { title: "New IOCs", value: stats.iocs, delta: stats.iocsDelta, note: "Unique indicators on record", icon: Crosshair, hi: true },
    { title: "Suspicious Threats", value: stats.suspicious, delta: stats.suspiciousDelta, note: "Needs a human look", icon: TriangleAlert },
    { title: "Scans Analysed", value: stats.scans, delta: stats.scansDelta, note: "Verdicts in the report store", icon: Gauge },
  ];

  function upgrade() {
    const checkout = billing.data?.teams.checkout;
    if (checkout) window.open(checkout, "_blank", "noreferrer");
    else window.alert(billing.data?.teams.hint ?? "Teams checkout is not configured yet (set STRIPE_PAYMENT_LINK).");
  }

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <aside className="flex w-60 shrink-0 flex-col border-r border-border bg-chrome px-4 py-6">
        <div className="flex items-center gap-2 px-2">
          <span className="grid h-8 w-8 place-items-center rounded-[3px] bg-foreground text-background"><User size={18} /></span>
          <span className="text-2xl">Sentinel</span><span className="text-sm">Nexus</span>
        </div>
        <p className="mt-10 px-2 text-sm uppercase text-muted-foreground">Overview</p>
        <nav className="mt-3 space-y-1 text-sm">
          {NAV.map((n, i) =>
            n.heading ? (
              <p key={i} className="px-2 pb-1 pt-3 text-muted-foreground">{n.label}</p>
            ) : (
              <div key={i} className={`flex items-center gap-3 rounded-[3px] px-3 py-2.5 ${i === 0 ? "nav-active-glow text-foreground" : "nav-link text-gray-400 hover:text-white"}`}>
                {n.icon && <n.icon size={18} />} <span>{n.label}</span>
              </div>
            ),
          )}
        </nav>
        <div className="relative mt-auto pt-12">
          <div className="absolute left-1/2 top-2 grid h-20 w-20 -translate-x-1/2 rotate-45 place-items-center rounded-[3px] border border-primary bg-secondary">
            <img src={avatar} alt="User" width={816} height={816} loading="lazy" className="h-12 w-12 -rotate-45 rounded-full object-cover" />
          </div>
          <div className="panel px-4 pb-5 pt-14 text-center">
            <p className="font-semibold">Go Premium Now!</p>
            <p className="mt-2 text-sm text-muted-foreground">
              {billing.data ? `${billing.data.teams.price} for unlimited scans and the staff inbox API.` : "Upgrade to pro for unlimited features!"}
            </p>
            <button onClick={upgrade} className="mt-4 w-full rounded-[3px] border border-primary py-2.5 text-sm">Upgrade Now</button>
          </div>
        </div>
      </aside>

      <main className="content-gradient min-w-0 flex-1">
        <header className="flex items-center gap-4 border-b border-border bg-chrome px-6 py-4">
          <Home size={18} className="text-muted-foreground" />
          <ChevronRight size={14} className="text-muted-foreground" />
          <p className="text-sm">Dashboard</p>
          <label className="ml-auto flex w-56 cursor-text items-center gap-2 rounded-[3px] border border-border px-3 py-2 text-sm text-muted-foreground"><Search size={16} /><input placeholder="Search" className="w-full bg-transparent text-foreground outline-none placeholder:text-muted-foreground" /></label>
          <button
            type="button"
            onClick={() => setDark((v) => !v)}
            aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}
            title={dark ? "Switch to light theme" : "Switch to dark theme"}
            className="cursor-pointer rounded-[3px] border border-border p-2"
          >
            {dark ? <Sun size={16} /> : <Moon size={16} />}
          </button>
          <button onClick={() => history.refetch()} className="flex cursor-pointer items-center gap-2 rounded-[3px] border border-border px-3 py-2 text-sm">
            <RefreshCw size={16} className={`text-primary ${history.isFetching ? "animate-spin" : ""}`} /> Refresh Data
          </button>
        </header>

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
                <button className="flex items-center gap-2 rounded-[3px] border border-border px-3 py-2 text-sm"><User size={14} /> Last 7 Days <ChevronDown size={14} /></button>
              </div>
              <div className="chart-bg grid-bg relative h-80 overflow-hidden rounded-[3px] border border-border">
                <svg viewBox="0 0 430 260" className="h-full w-full" preserveAspectRatio="none">
                  <defs><filter id="g"><feGaussianBlur stdDeviation="4" /></filter></defs>
                  {guides.map((p, i) => (
                    <line key={i} x1={p.x} y1={p.y} x2={p.x} y2={p.y + 60} className="stroke-primary" strokeDasharray="2 3" opacity={0.6} />
                  ))}
                  <polyline points={trendPolyline(trend)} fill="none" className="stroke-primary" strokeWidth={6} filter="url(#g)" />
                  <polyline points={trendPolyline(trend)} fill="none" className="stroke-primary" strokeWidth={2.5} strokeDasharray="1 4" strokeLinecap="round" />
                  {labels.map((p) => (
                    <text key={p.x} x={p.x} y={Math.max(10, p.y - 10)} className="fill-primary" fontSize={8}>{p.label}</text>
                  ))}
                </svg>
                <p className="absolute bottom-4 w-full text-center text-xs text-muted-foreground">
                  {scans.length === 0 ? "No verdicts in the last 7 days" : "Verdicts per day · agent scans in the sandbox"}
                </p>
              </div>
            </div>
            <div>
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-2xl">Severity Distribution</h2>
                <button className="rounded-[3px] border border-primary bg-secondary p-2"><MoreVertical size={16} /></button>
              </div>
              <div className="chart-bg relative h-80 overflow-hidden rounded-[3px] border border-border">
                <div className="absolute left-1/2 top-1/2 h-56 w-64 -translate-x-1/2 -translate-y-[58%]">
                  <div className="pill-glow absolute left-[28%] top-0 flex h-44 w-24 rotate-[30deg] items-start justify-center rounded-full pt-8 [writing-mode:horizontal-tb] text-sm font-semibold"><span className="-rotate-[30deg]">Critical {distribution.critical}%</span></div>
                  <div className="pill-glow absolute bottom-0 -left-6 z-10 flex h-24 w-40 items-center justify-start rounded-full pl-6 text-sm font-semibold">High {distribution.high}%</div>
                  <div className="pill-glow absolute bottom-0 -right-6 flex h-24 w-40 -scale-x-100 items-center justify-start pl-6 rounded-full text-sm font-semibold"><span className="-scale-x-100">Low {distribution.low}%</span></div>
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
                <a href={reportUrl(r.id)} target="_blank" rel="noreferrer" className="w-fit">View</a>
              </div>
            ))}
            <p className="px-6 text-xs text-muted-foreground">
              Reports keep the verdict, reasons, indicators and generated code — never the file contents.
            </p>
          </section>
        </div>
      </main>
    </div>
  );
}
