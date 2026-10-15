import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Check, Download, Link2, RefreshCw, Search, ShieldAlert, TriangleAlert, Gauge, X,
} from "lucide-react";

import { FilterDropdown } from "@/components/filter-dropdown";
import { WorkspaceShell } from "@/components/workspace-shell";
import { deleteReport, fetchHistory, fetchReport, reportUrl } from "@/lib/api";
import type { ScanResult, ScanSummary, Verdict } from "@/lib/api";
import { relativeTime, shortDate, verdictTone } from "@/lib/threat-stats";
import { navigate, useRoute } from "@/lib/route";

const PAGE_SIZE = 10;

const VERDICT_TABS = [
  { value: "all", label: "All reports" },
  { value: "Malicious", label: "Malicious" },
  { value: "Suspicious", label: "Suspicious" },
  { value: "Verified", label: "Verified" },
] as const;
type VerdictFilter = (typeof VERDICT_TABS)[number]["value"];

const KIND_OPTIONS = [
  { value: "all", label: "All types" },
  { value: "email", label: "Email" },
  { value: "file", label: "File" },
  { value: "deep", label: "Deep scans" },
] as const;
type KindFilter = (typeof KIND_OPTIONS)[number]["value"];

const DATE_OPTIONS = [
  { value: "all", label: "All time" },
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
] as const;
type DateFilter = (typeof DATE_OPTIONS)[number]["value"];

const SORT_OPTIONS = [
  { value: "newest", label: "Newest first" },
  { value: "oldest", label: "Oldest first" },
  { value: "score", label: "Highest score" },
] as const;
type SortKey = (typeof SORT_OPTIONS)[number]["value"];

const DAY_MS = 24 * 60 * 60 * 1000;

function isVerdict(v: string | null): v is Verdict {
  return v === "Verified" || v === "Suspicious" || v === "Malicious";
}

function scanTypeLabel(s: ScanSummary) {
  if (s.deep) return "Deep scan";
  return s.kind === "email" ? "Email" : "File";
}

export function Reports() {
  const history = useQuery({ queryKey: ["history"], queryFn: fetchHistory, refetchInterval: 30_000 });
  const scans = history.data ?? [];
  const { params } = useRoute();

  const [tab, setTab] = useState<VerdictFilter>(() => {
    const initial = params.get("verdict");
    return isVerdict(initial) ? initial : "all";
  });
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<KindFilter>("all");
  const [date, setDate] = useState<DateFilter>("all");
  const [sort, setSort] = useState<SortKey>("newest");
  const [visible, setVisible] = useState(PAGE_SIZE);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<ScanResult | null>(null);
  const [detailPending, setDetailPending] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [showCode, setShowCode] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [drawerError, setDrawerError] = useState<string | null>(null);

  useEffect(() => {
    setVisible(PAGE_SIZE);
  }, [tab, query, kind, date, sort]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const cutoff =
      date === "24h" ? Date.now() - DAY_MS : date === "7d" ? Date.now() - 7 * DAY_MS : date === "30d" ? Date.now() - 30 * DAY_MS : 0;
    const rows = scans.filter((s) => {
      if (tab !== "all" && s.verdict !== tab) return false;
      if (kind === "deep" ? !s.deep : kind !== "all" && s.kind !== kind) return false;
      if (cutoff > 0) {
        const t = Date.parse(s.t);
        if (!Number.isFinite(t) || t < cutoff) return false;
      }
      if (!q) return true;
      return s.id.toLowerCase().includes(q) || s.filename.toLowerCase().includes(q);
    });
    const byTime = (a: ScanSummary, b: ScanSummary) => Date.parse(b.t) - Date.parse(a.t);
    if (sort === "oldest") rows.sort((a, b) => -byTime(a, b));
    else if (sort === "score") rows.sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
    else rows.sort(byTime);
    return rows;
  }, [scans, tab, query, kind, date, sort]);

  const malicious = scans.filter((s) => s.verdict === "Malicious").length;
  const suspicious = scans.filter((s) => s.verdict === "Suspicious").length;
  const verified = scans.filter((s) => s.verdict === "Verified").length;

  const shown = filtered.slice(0, visible);
  const summary: ScanSummary | undefined = scans.find((s) => s.id === selectedId) ?? undefined;

  useEffect(() => {
    setDetail(null);
    setDetailError(null);
    setShowCode(false);
    setConfirmingDelete(false);
    setCopied(null);
    setDrawerError(null);
    if (!selectedId) {
      setDetailPending(false);
      return;
    }
    let cancelled = false;
    setDetailPending(true);
    fetchReport(selectedId)
      .then((r) => {
        if (!cancelled) {
          setDetail(r);
          setDetailPending(false);
        }
      })
      .catch((e) => {
        if (!cancelled) {
          setDetailError(e instanceof Error ? e.message : String(e));
          setDetailPending(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [selectedId]);

  useEffect(() => {
    if (!selectedId) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setSelectedId(null);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [selectedId]);

  async function copyText(text: string, key: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      window.setTimeout(() => setCopied((c) => (c === key ? null : c)), 2000);
    } catch {
      setDrawerError("Copy unavailable in this browser.");
    }
  }

  function reportLink(id: string) {
    return new URL(reportUrl(id), window.location.origin).href;
  }

  function exportJson() {
    if (typeof URL.createObjectURL !== "function" || !selectedId) {
      setDrawerError("Export unavailable in this browser.");
      return;
    }
    const payload = detail ?? summary;
    if (!payload) return;
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `phishshield-report-${selectedId}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  async function remove() {
    if (!selectedId) return;
    setDeleting(true);
    setDrawerError(null);
    try {
      await deleteReport(selectedId);
      setSelectedId(null);
      await history.refetch();
    } catch (e) {
      setDrawerError(e instanceof Error ? e.message : String(e));
    } finally {
      setDeleting(false);
    }
  }

  const SUMMARY = [
    { title: "Total reports", value: scans.length, note: "Scan records on file", icon: Gauge },
    { title: "Malicious", value: malicious, note: "Highest-severity verdicts", icon: ShieldAlert },
    { title: "Suspicious", value: suspicious, note: "Needs a human look", icon: TriangleAlert },
    { title: "Verified / low risk", value: verified, note: "No significant indicators", icon: Gauge },
  ];

  const reasons = detail?.reasons ?? summary?.reasons ?? [];
  const iocs = detail?.iocs ?? summary?.iocs;
  const runs = detail?.runs ?? summary?.runs;
  const agreement = detail?.agreement ?? summary?.agreement;
  const agentCode = detail?.agent_code;
  const score = detail?.score ?? summary?.score ?? 0;

  return (
    <WorkspaceShell
      section="Reports"
      actions={
        <button onClick={() => history.refetch()} className="flex cursor-pointer items-center gap-2 rounded-[3px] border border-border px-3 py-2 text-sm text-on-chrome">
          <RefreshCw size={16} className={`text-primary ${history.isFetching ? "animate-spin" : ""}`} /> Refresh Data
        </button>
      }
    >
      <div className="space-y-8 p-6">
        <section className="grid grid-cols-2 gap-5 xl:grid-cols-4">
          {SUMMARY.map((k) => (
            <div key={k.title} className="kpi-card p-5 text-center">
              <span className="mx-auto grid h-10 w-10 place-items-center rounded-full border border-border bg-secondary"><k.icon size={16} /></span>
              <p className="mt-3">{k.title}</p>
              <p className="mt-2 text-3xl text-primary">{k.value}</p>
              <div className="mt-4 border-t border-border pt-4 text-xs">
                <span className="text-muted-foreground">{k.note}</span>
              </div>
            </div>
          ))}
        </section>

        <div className="panel flex flex-wrap items-center gap-3 p-4">
          <div className="flex w-fit gap-1 rounded-[3px] border border-border bg-secondary p-0.5 text-sm">
            {VERDICT_TABS.map((t) => (
              <button
                key={t.value}
                type="button"
                onClick={() => setTab(t.value)}
                aria-pressed={tab === t.value}
                className={`cursor-pointer rounded-[3px] px-4 py-2 ${tab === t.value ? "bg-card text-foreground" : "text-muted-foreground"}`}
              >
                {t.label}
              </button>
            ))}
          </div>
          <label className="flex w-56 cursor-text items-center gap-2 rounded-[3px] border border-border bg-secondary px-4 py-2.5 text-sm text-muted-foreground">
            <Search size={16} />
            <input
              placeholder="Search reports or IDs"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full bg-transparent text-foreground outline-none placeholder:text-muted-foreground"
            />
          </label>
          <FilterDropdown label="Scan type" value={kind} options={KIND_OPTIONS} onChange={setKind} />
          <FilterDropdown label="Date range" value={date} options={DATE_OPTIONS} onChange={setDate} />
          <FilterDropdown label="Sort reports" value={sort} options={SORT_OPTIONS} onChange={setSort} />
        </div>

        <section className="space-y-3">
          <div className="overflow-x-auto">
            <div className="min-w-[860px] space-y-3">
              <div className="grid grid-cols-[2fr_1fr_0.7fr_0.9fr_1fr_auto] gap-4 px-6 text-sm text-muted-foreground">
                <span>Report</span><span>Verdict</span><span>Score</span><span>Type</span><span>Created</span><span>Actions</span>
              </div>
              {history.isPending && (
                <div className="row-panel px-6 py-5 text-sm text-muted-foreground">Loading reports…</div>
              )}
              {history.isError && (
                <div className="row-panel px-6 py-5 text-sm text-destructive">
                  Could not load reports: {(history.error as Error).message}
                  <button type="button" onClick={() => history.refetch()} className="ml-3 cursor-pointer underline">Retry</button>
                </div>
              )}
              {!history.isPending && !history.isError && scans.length === 0 && (
                <div className="row-panel space-y-3 px-6 py-8 text-center">
                  <p className="text-sm text-muted-foreground">No reports yet — run your first scan to start the archive.</p>
                  <button
                    type="button"
                    onClick={() => navigate("#/")}
                    className="cursor-pointer rounded-[3px] bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground"
                  >
                    Start your first scan
                  </button>
                </div>
              )}
              {!history.isPending && !history.isError && scans.length > 0 && filtered.length === 0 && (
                <div className="row-panel px-6 py-5 text-sm text-muted-foreground">
                  No reports match these filters.
                </div>
              )}
              {shown.map((r) => (
                <div key={r.id} className="row-panel grid grid-cols-[2fr_1fr_0.7fr_0.9fr_1fr_auto] items-center gap-4 px-6 py-4 text-sm">
                  <span className="min-w-0">
                    <span className="block truncate">{r.filename}</span>
                    <span className="block truncate font-mono text-xs text-muted-foreground">{r.id}</span>
                  </span>
                  <span className={verdictTone(r.verdict)}>{r.verdict}</span>
                  <span>{r.score}</span>
                  <span className="text-muted-foreground">{scanTypeLabel(r)}</span>
                  <span className="text-muted-foreground">{shortDate(r.t)}</span>
                  <span className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setSelectedId(r.id)}
                      className="cursor-pointer rounded-[3px] border border-border px-3 py-1.5 text-xs"
                    >
                      Open
                    </button>
                    <button
                      type="button"
                      onClick={() => copyText(reportLink(r.id), r.id)}
                      aria-label={`Copy report link for ${r.filename}`}
                      title="Copy report link"
                      className="cursor-pointer rounded-[3px] border border-border p-1.5"
                    >
                      {copied === r.id ? <Check size={14} /> : <Link2 size={14} />}
                    </button>
                  </span>
                </div>
              ))}
            </div>
          </div>
          {visible < filtered.length && (
            <button
              type="button"
              onClick={() => setVisible((v) => v + PAGE_SIZE)}
              className="w-full cursor-pointer rounded-[3px] border border-border px-3 py-2.5 text-sm text-muted-foreground"
            >
              Show more ({filtered.length - visible} remaining)
            </button>
          )}
        </section>
      </div>

      {summary && (
        <div className="fixed inset-0 z-30">
          <div className="absolute inset-0 bg-black/60" onClick={() => setSelectedId(null)} aria-hidden="true" />
          <aside
            role="dialog"
            aria-modal="true"
            aria-label={`Report: ${summary.filename}`}
            className="absolute inset-y-0 right-0 flex w-full max-w-2xl flex-col gap-6 overflow-y-auto border-l border-border bg-card p-6"
          >
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <p className="text-xs uppercase tracking-wide text-muted-foreground">Scan report · {summary.id}</p>
                <p className="mt-1 break-words text-2xl font-semibold">{summary.filename}</p>
                <p className={`mt-2 flex items-center gap-2 text-lg font-semibold ${verdictTone(summary.verdict)}`}>
                  {summary.verdict}
                  <span className="text-sm font-normal text-muted-foreground">Risk score {score}</span>
                </p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedId(null)}
                aria-label="Close report"
                className="cursor-pointer rounded-[3px] border border-border p-2"
              >
                <X size={16} />
              </button>
            </div>

            {detailPending && (
              <p className="text-sm text-muted-foreground">Loading full report…</p>
            )}
            {detailError && (
              <p className="text-sm text-destructive">
                Could not load full details ({detailError}). Showing summary below.
              </p>
            )}

            <dl className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-sm">
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">Analysis mode</dt>
                <dd>{(detail?.deep ?? summary.deep) ? "Deep scan" : "Standard"}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">Scanned</dt>
                <dd>{shortDate(summary.t)} · {relativeTime(summary.t)}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">Execution mode</dt>
                <dd>{detail?.mode ?? summary.mode ?? "—"}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">Report ID</dt>
                <dd className="truncate font-mono text-xs">{summary.id}</dd>
              </div>
            </dl>

            <div>
              <p className="text-sm text-muted-foreground">Why this was flagged</p>
              {reasons.length === 0 ? (
                <p className="mt-2 text-sm text-muted-foreground">No reasons recorded.</p>
              ) : (
                <ul className="mt-2 space-y-2">
                  {reasons.map((reason) => (
                    <li key={reason} className="rounded-[3px] border border-border bg-secondary/30 px-3 py-2 text-sm">
                      {reason}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div>
              <p className="text-sm text-muted-foreground">Indicators of compromise</p>
              {!iocs || iocs.domains.length + iocs.urls.length + (iocs.sha256 ? 1 : 0) === 0 ? (
                <p className="mt-2 text-sm text-muted-foreground">No indicators extracted.</p>
              ) : (
                <div className="mt-2 flex flex-wrap gap-2">
                  {[iocs.sha256, ...iocs.domains, ...iocs.urls]
                    .filter(Boolean)
                    .map((ioc) => (
                      <span
                        key={ioc}
                        className="max-w-full truncate rounded-[3px] border border-border bg-secondary px-2 py-1 font-mono text-xs"
                      >
                        {ioc}
                      </span>
                    ))}
                </div>
              )}
              <a href="#/indicators" className="mt-2 inline-block text-xs text-primary underline">
                Open in Indicators
              </a>
            </div>

            {runs && runs.length > 0 && (
              <div>
                <p className="text-sm text-muted-foreground">Deep scan comparison</p>
                <ul className="mt-2 space-y-2 text-sm">
                  {runs.map((run) => (
                    <li key={run.profile} className="flex items-center justify-between rounded-[3px] border border-border px-3 py-2">
                      <span className="text-muted-foreground">{run.profile} variant</span>
                      <span className={verdictTone(run.verdict)}>
                        {run.verdict} · {run.score}
                      </span>
                    </li>
                  ))}
                </ul>
                <p className="mt-2 text-xs text-muted-foreground">
                  {agreement
                    ? "Both variants agree — harsher verdict wins."
                    : "Variants disagree — the harsher verdict wins."}
                </p>
              </div>
            )}

            {agentCode ? (
              <div>
                <div className="flex items-center justify-between">
                  <p className="text-sm text-muted-foreground">Agent analysis</p>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => setShowCode((v) => !v)}
                      aria-expanded={showCode}
                      className="cursor-pointer rounded-[3px] border border-border px-3 py-1.5 text-xs"
                    >
                      {showCode ? "Hide code" : "Show code"}
                    </button>
                    <button
                      type="button"
                      onClick={() => copyText(agentCode, "code")}
                      className="cursor-pointer rounded-[3px] border border-border px-3 py-1.5 text-xs"
                    >
                      {copied === "code" ? "Copied" : "Copy code"}
                    </button>
                  </div>
                </div>
                {showCode && (
                  <pre className="chart-bg mt-2 max-h-96 overflow-auto rounded-[3px] border border-border p-4 font-mono text-xs leading-relaxed text-foreground">
                    {agentCode}
                  </pre>
                )}
              </div>
            ) : (
              !detailPending && (
                <p className="text-xs text-muted-foreground">No agent code recorded for this report.</p>
              )
            )}

            <div className="mt-auto space-y-2 border-t border-border pt-4">
              <p className="text-sm text-muted-foreground">Share this report</p>
              <p className="text-xs text-muted-foreground">
                Anyone with the public link may be able to view its contents.
              </p>
              <div className="flex flex-wrap gap-2">
                <a
                  href={reportUrl(summary.id)}
                  target="_blank"
                  rel="noreferrer"
                  className="rounded-[3px] bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground"
                >
                  Open full report
                </a>
                <button
                  type="button"
                  onClick={() => copyText(reportLink(summary.id), "link")}
                  className="cursor-pointer rounded-[3px] border border-border px-4 py-2 text-sm"
                >
                  {copied === "link" ? "Copied" : "Copy report link"}
                </button>
                <button
                  type="button"
                  onClick={() => copyText(summary.id, "id")}
                  className="cursor-pointer rounded-[3px] border border-border px-4 py-2 text-sm"
                >
                  {copied === "id" ? "Copied" : "Copy report ID"}
                </button>
                <button
                  type="button"
                  onClick={exportJson}
                  className="flex cursor-pointer items-center gap-2 rounded-[3px] border border-border px-4 py-2 text-sm"
                >
                  <Download size={14} /> Export JSON
                </button>
                {confirmingDelete ? (
                  <>
                    <button
                      type="button"
                      onClick={remove}
                      disabled={deleting}
                      className="cursor-pointer rounded-[3px] border border-destructive px-4 py-2 text-sm text-destructive disabled:opacity-50"
                    >
                      {deleting ? "Deleting…" : "Confirm delete"}
                    </button>
                    <button
                      type="button"
                      onClick={() => setConfirmingDelete(false)}
                      className="cursor-pointer rounded-[3px] border border-border px-4 py-2 text-sm"
                    >
                      Cancel
                    </button>
                  </>
                ) : (
                  <button
                    type="button"
                    onClick={() => setConfirmingDelete(true)}
                    className="cursor-pointer rounded-[3px] border border-border px-4 py-2 text-sm text-muted-foreground"
                  >
                    Delete
                  </button>
                )}
              </div>
              {drawerError && <p className="text-sm text-destructive">{drawerError}</p>}
            </div>
          </aside>
        </div>
      )}
    </WorkspaceShell>
  );
}
