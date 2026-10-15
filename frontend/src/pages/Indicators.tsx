import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Check, Fingerprint, Globe, Link2, RefreshCw, Search, ShieldAlert, X } from "lucide-react";

import { FilterDropdown } from "@/components/filter-dropdown";
import { WorkspaceShell } from "@/components/workspace-shell";
import { fetchHistory, reportUrl } from "@/lib/api";
import type { IndicatorAssessment, IndicatorType } from "@/lib/threat-stats";
import {
  brandInReasons,
  buildIndicators,
  relativeTime,
  shortDate,
  verdictTone,
} from "@/lib/threat-stats";

const PAGE_SIZE = 10;

const TYPE_TABS = [
  { value: "all", label: "All types" },
  { value: "Domain", label: "Domains" },
  { value: "URL", label: "URLs" },
  { value: "IP address", label: "IP addresses" },
  { value: "SHA-256", label: "File hashes" },
] as const;
type TypeFilter = (typeof TYPE_TABS)[number]["value"];

const ASSESSMENT_OPTIONS = [
  { value: "all", label: "All assessments" },
  { value: "Malicious", label: "Malicious" },
  { value: "Suspicious", label: "Suspicious" },
  { value: "Verified", label: "Verified" },
  { value: "Unassessed", label: "Unassessed" },
] as const;
type AssessmentFilter = (typeof ASSESSMENT_OPTIONS)[number]["value"];

const SORT_OPTIONS = [
  { value: "reports", label: "Most reports" },
  { value: "recent", label: "Recently seen" },
  { value: "oldest", label: "Oldest first" },
] as const;
type SortKey = (typeof SORT_OPTIONS)[number]["value"];

function assessTone(assessment: IndicatorAssessment) {
  if (assessment === "Malicious") return "text-destructive";
  if (assessment === "Suspicious") return "text-warning";
  if (assessment === "Verified") return "text-success";
  return "text-muted-foreground";
}

function assessDot(assessment: IndicatorAssessment) {
  if (assessment === "Malicious") return "bg-destructive";
  if (assessment === "Suspicious") return "bg-warning";
  if (assessment === "Verified") return "bg-success";
  return "bg-muted-foreground";
}

function sourceQueryFor(value: string, type: IndicatorType) {
  if (type !== "URL") return value;
  try {
    return new URL(value).hostname || value;
  } catch {
    return value;
  }
}

function typeLabel(type: IndicatorType) {
  return type === "IP address" ? "IP" : type === "SHA-256" ? "SHA-256" : type;
}

export function Indicators() {
  const history = useQuery({ queryKey: ["history"], queryFn: fetchHistory, refetchInterval: 30_000 });
  const scans = history.data ?? [];

  const [tab, setTab] = useState<TypeFilter>("all");
  const [query, setQuery] = useState("");
  const [assessment, setAssessment] = useState<AssessmentFilter>("all");
  const [sort, setSort] = useState<SortKey>("reports");
  const [visible, setVisible] = useState(PAGE_SIZE);
  const [selected, setSelected] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);

  useEffect(() => {
    setVisible(PAGE_SIZE);
  }, [tab, query, assessment, sort]);

  const records = useMemo(() => buildIndicators(scans), [scans]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const rows = records.filter((r) => {
      if (tab !== "all" && r.type !== tab) return false;
      if (assessment !== "all" && r.assessment !== assessment) return false;
      if (!q) return true;
      return r.value.toLowerCase().includes(q);
    });
    if (sort === "recent") rows.sort((a, b) => b.lastSeen - a.lastSeen);
    else if (sort === "oldest") rows.sort((a, b) => a.firstSeen - b.firstSeen);
    return rows;
  }, [records, tab, query, assessment, sort]);

  const total = records.length;
  const highRisk = records.filter((r) => r.assessment === "Malicious").length;
  const domains = records.filter((r) => r.type === "Domain").length;
  const hashes = records.filter((r) => r.type === "SHA-256").length;

  const shown = filtered.slice(0, visible);
  const active = records.find((r) => r.value === selected) ?? undefined;
  const activeBrand = active ? brandInReasons(active.evidence) : null;

  useEffect(() => {
    if (!active) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setSelected(null);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [active]);

  async function copyText(text: string, key: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setCopyError(null);
      window.setTimeout(() => setCopied((c) => (c === key ? null : c)), 2000);
    } catch {
      setCopyError("Copy unavailable in this browser.");
    }
  }

  const SUMMARY = [
    { title: "Total indicators", value: total, note: "Deduped across scan records", icon: Fingerprint },
    { title: "High-risk indicators", value: highRisk, note: "Named in malicious evidence", icon: ShieldAlert },
    { title: "Domains", value: domains, note: "Observed indicator domains", icon: Globe },
    { title: "File hashes", value: hashes, note: "SHA-256 of scanned files", icon: Fingerprint },
  ];

  return (
    <WorkspaceShell
      section="Indicators"
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
          <div className="flex w-fit flex-wrap gap-1 rounded-[3px] border border-border bg-secondary p-0.5 text-sm">
            {TYPE_TABS.map((t) => (
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
              placeholder="Search indicators"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full bg-transparent text-foreground outline-none placeholder:text-muted-foreground"
            />
          </label>
          <FilterDropdown label="Assessment" value={assessment} options={ASSESSMENT_OPTIONS} onChange={setAssessment} />
          <FilterDropdown label="Sort indicators" value={sort} options={SORT_OPTIONS} onChange={setSort} />
        </div>

        <section className="space-y-3">
          <div className="overflow-x-auto">
            <div className="min-w-[860px] space-y-3">
              <div className="grid grid-cols-[2fr_0.9fr_1fr_0.7fr_0.9fr_0.9fr_auto] gap-4 px-6 text-sm text-muted-foreground">
                <span>Indicator</span><span>Type</span><span>Assessment</span><span>Reports</span><span>First seen</span><span>Last seen</span><span>Actions</span>
              </div>
              {history.isPending && (
                <div className="row-panel px-6 py-5 text-sm text-muted-foreground">Loading indicators…</div>
              )}
              {history.isError && (
                <div className="row-panel px-6 py-5 text-sm text-destructive">
                  Could not load indicators: {(history.error as Error).message}
                </div>
              )}
              {!history.isPending && !history.isError && filtered.length === 0 && (
                <div className="row-panel px-6 py-5 text-sm text-muted-foreground">
                  No indicators match these filters.
                </div>
              )}
              {copyError && (
                <div className="row-panel px-6 py-3 text-sm text-destructive">{copyError}</div>
              )}
              {shown.map((r) => (
                <div key={`${r.type}:${r.value}`} className="row-panel grid grid-cols-[2fr_0.9fr_1fr_0.7fr_0.9fr_0.9fr_auto] items-center gap-4 px-6 py-4 text-sm">
                  <span className="truncate font-mono text-xs">{r.value}</span>
                  <span className="text-muted-foreground">{typeLabel(r.type)}</span>
                  <span className={`flex items-center gap-1.5 ${assessTone(r.assessment)}`}>
                    <span className={`h-2 w-2 shrink-0 rounded-full ${assessDot(r.assessment)}`} />
                    {r.assessment}
                  </span>
                  <span>{r.reports}</span>
                  <span className="text-muted-foreground">{r.firstSeen ? shortDate(new Date(r.firstSeen).toISOString()) : "—"}</span>
                  <span className="text-muted-foreground">{r.lastSeen ? relativeTime(new Date(r.lastSeen).toISOString()) : "—"}</span>
                  <span className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => copyText(r.value, r.value)}
                      aria-label={`Copy indicator ${r.value}`}
                      title="Copy value"
                      className="cursor-pointer rounded-[3px] border border-border p-1.5"
                    >
                      {copied === r.value ? <Check size={14} /> : <Link2 size={14} />}
                    </button>
                    <button
                      type="button"
                      onClick={() => setSelected(r.value)}
                      className="cursor-pointer rounded-[3px] border border-border px-3 py-1.5 text-xs"
                    >
                      View details
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

      {active && (
        <div className="fixed inset-0 z-30">
          <div className="absolute inset-0 bg-black/60" onClick={() => setSelected(null)} aria-hidden="true" />
          <aside
            role="dialog"
            aria-modal="true"
            aria-label={`Indicator details: ${active.value}`}
            className="absolute inset-y-0 right-0 flex w-full max-w-md flex-col gap-6 overflow-y-auto border-l border-border bg-card p-6"
          >
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <p className={`flex items-center gap-2 text-2xl font-semibold ${assessTone(active.assessment)}`}>
                  {active.assessment}
                </p>
                <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{active.value}</p>
              </div>
              <button
                type="button"
                onClick={() => setSelected(null)}
                aria-label="Close indicator details"
                className="cursor-pointer rounded-[3px] border border-border p-2"
              >
                <X size={16} />
              </button>
            </div>

            <dl className="space-y-1.5 text-sm">
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">Type</dt>
                <dd>{active.type}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">Occurrences</dt>
                <dd>{active.reports} linked report{active.reports === 1 ? "" : "s"}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">First observed</dt>
                <dd>{active.firstSeen ? shortDate(new Date(active.firstSeen).toISOString()) : "—"}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">Last observed</dt>
                <dd>{active.lastSeen ? shortDate(new Date(active.lastSeen).toISOString()) : "—"}</dd>
              </div>
              {activeBrand && (
                <div className="flex justify-between gap-4">
                  <dt className="text-muted-foreground">Associated brand</dt>
                  <dd>{activeBrand}</dd>
                </div>
              )}
            </dl>

            <div>
              <p className="text-sm text-muted-foreground">Evidence and context</p>
              {active.evidence.length === 0 ? (
                <p className="mt-2 text-sm text-muted-foreground">
                  No detection reason names this artifact — it is unassessed beyond appearing in linked reports.
                </p>
              ) : (
                <ul className="mt-2 space-y-2">
                  {active.evidence.map((reason) => (
                    <li key={reason} className="rounded-[3px] border border-border bg-secondary/30 px-3 py-2 text-sm">
                      {reason}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div>
              <p className="text-sm text-muted-foreground">Related reports</p>
              <ul className="mt-2 space-y-2">
                {active.reportIds.map((rep) => (
                  <li key={rep.id} className="flex items-center gap-2 text-sm">
                    <span className={verdictTone(rep.verdict)}>{rep.verdict}</span>
                    <span className="min-w-0 flex-1 truncate">{rep.filename}</span>
                    <span className="shrink-0 text-xs text-muted-foreground">{relativeTime(rep.t)}</span>
                    <a href={reportUrl(rep.id)} target="_blank" rel="noreferrer" className="shrink-0 text-xs text-primary underline">
                      View
                    </a>
                  </li>
                ))}
              </ul>
            </div>

            <div className="mt-auto space-y-2 border-t border-border pt-4">
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => copyText(active.value, active.value)}
                  className="cursor-pointer rounded-[3px] border border-border px-4 py-2 text-sm"
                >
                  {copied === active.value ? "Copied" : "Copy indicator"}
                </button>
                <a
                  href={`#/sources?q=${encodeURIComponent(sourceQueryFor(active.value, active.type))}`}
                  className="rounded-[3px] border border-border px-4 py-2 text-sm"
                >
                  View in Sources
                </a>
              </div>
              {copyError && <p className="text-sm text-destructive">{copyError}</p>}
            </div>
          </aside>
        </div>
      )}
    </WorkspaceShell>
  );
}
