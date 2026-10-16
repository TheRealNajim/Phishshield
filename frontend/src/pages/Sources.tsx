import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Globe, RefreshCw, Repeat, Search, ShieldAlert, Tag, X } from "lucide-react";

import { FilterDropdown } from "@/components/filter-dropdown";
import { ScanDetailModal } from "@/components/scan-detail-modal";
import { WorkspaceShell } from "@/components/workspace-shell";
import { fetchHistory } from "@/lib/api";
import type { Verdict } from "@/lib/api";
import { buildSources, relativeTime, shortDate, verdictTone } from "@/lib/threat-stats";
import { useRoute } from "@/lib/route";

const PAGE_SIZE = 10;

const TYPE_OPTIONS = [
  { value: "all", label: "All types" },
  { value: "Lookalike domain", label: "Lookalike" },
  { value: "Link destination", label: "Link destination" },
  { value: "Observed domain", label: "Observed" },
] as const;
type TypeFilter = (typeof TYPE_OPTIONS)[number]["value"];

const VERDICT_OPTIONS = [
  { value: "all", label: "All verdicts" },
  { value: "Malicious", label: "Malicious" },
  { value: "Suspicious", label: "Suspicious" },
  { value: "Verified", label: "Verified" },
] as const;
type VerdictFilter = (typeof VERDICT_OPTIONS)[number]["value"];

function verdictDot(verdict: Verdict) {
  return verdict === "Malicious" ? "bg-destructive" : verdict === "Suspicious" ? "bg-warning" : "bg-success";
}

export function Sources() {
  const history = useQuery({ queryKey: ["history"], queryFn: fetchHistory, refetchInterval: 30_000 });
  const scans = history.data ?? [];
  const { params } = useRoute();

  const [query, setQuery] = useState(params.get("q") ?? "");
  const [type, setType] = useState<TypeFilter>("all");
  const [verdict, setVerdict] = useState<VerdictFilter>("all");
  const [repeatOnly, setRepeatOnly] = useState(false);
  const [visible, setVisible] = useState(PAGE_SIZE);
  const [selected, setSelected] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [viewId, setViewId] = useState<string | null>(null);

  useEffect(() => {
    setVisible(PAGE_SIZE);
  }, [query, type, verdict, repeatOnly]);

  const records = useMemo(() => buildSources(scans), [scans]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return records.filter((r) => {
      if (type !== "all" && r.type !== type) return false;
      if (verdict !== "all" && r.verdict !== verdict) return false;
      if (repeatOnly && r.scans < 2) return false;
      if (!q) return true;
      return (
        r.source.includes(q) ||
        (r.brand ?? "").includes(q) ||
        r.type.toLowerCase().includes(q)
      );
    });
  }, [records, query, type, verdict, repeatOnly]);

  const unique = records.length;
  const malicious = records.filter((r) => r.verdict === "Malicious").length;
  const brands = new Set(records.map((r) => r.brand).filter(Boolean)).size;
  const repeat = records.filter((r) => r.scans > 1).length;

  const shown = filtered.slice(0, visible);
  const active: (typeof filtered)[number] | undefined = records.find((r) => r.source === selected) ?? undefined;

  function openSource(source: string) {
    setSelected(source);
    setCopied(false);
  }

  useEffect(() => {
    if (!active) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setSelected(null);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [active]);

  async function copySource() {
    if (!active) return;
    try {
      await navigator.clipboard.writeText(active.source);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable */
    }
  }

  const SUMMARY = [
    { title: "Unique domains", value: unique, note: "Observed across scan records", icon: Globe },
    { title: "Malicious sources", value: malicious, note: "Worst linked verdict: malicious", icon: ShieldAlert },
    { title: "Impersonated brands", value: brands, note: "Named in detection evidence", icon: Tag },
    { title: "Repeat sources", value: repeat, note: "Seen in multiple scans", icon: Repeat },
  ];

  return (
    <WorkspaceShell
      section="Sources"
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
          <label className="flex w-56 cursor-text items-center gap-2 rounded-[3px] border border-border bg-secondary px-4 py-2.5 text-sm text-muted-foreground">
            <Search size={16} />
            <input
              placeholder="Search domains or brands"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full bg-transparent text-foreground outline-none placeholder:text-muted-foreground"
            />
          </label>
          <FilterDropdown label="Source type" value={type} options={TYPE_OPTIONS} onChange={setType} />
          <FilterDropdown label="Source verdict" value={verdict} options={VERDICT_OPTIONS} onChange={setVerdict} />
          <button
            type="button"
            onClick={() => setRepeatOnly((v) => !v)}
            aria-pressed={repeatOnly}
            className={`flex cursor-pointer items-center gap-2 rounded-[3px] border px-4 py-2.5 text-sm ${repeatOnly ? "border-primary bg-secondary text-foreground" : "border-border text-muted-foreground"}`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${repeatOnly ? "bg-primary" : "bg-muted-foreground"}`} />
            Repeat sources
          </button>
        </div>

        <section className="space-y-3">
          <div className="mb-4">
            <h2 className="text-2xl">Observed sources</h2>
            <p className="text-sm text-muted-foreground">Verdicts reflect the worst linked scan — appearing in a message alone proves nothing more.</p>
          </div>
          <div className="overflow-x-auto">
            <div className="min-w-[760px] space-y-3">
              <div className="grid grid-cols-[1.5fr_1fr_1fr_0.8fr_0.6fr_0.9fr_auto] gap-4 px-6 text-sm text-muted-foreground">
                <span>Source</span><span>Type</span><span>Brand</span><span>Verdict</span><span>Scans</span><span>Last seen</span><span>Action</span>
              </div>
              {history.isPending && (
                <div className="row-panel px-6 py-5 text-sm text-muted-foreground">Loading sources…</div>
              )}
              {history.isError && (
                <div className="row-panel px-6 py-5 text-sm text-destructive">
                  Could not load sources: {(history.error as Error).message}
                </div>
              )}
              {!history.isPending && !history.isError && filtered.length === 0 && (
                <div className="row-panel px-6 py-5 text-sm text-muted-foreground">
                  No sources match these filters.
                </div>
              )}
              {shown.map((r) => (
                <button
                  key={r.source}
                  type="button"
                  onClick={() => openSource(r.source)}
                  className="row-panel grid w-full cursor-pointer grid-cols-[1.5fr_1fr_1fr_0.8fr_0.6fr_0.9fr_auto] items-center gap-4 px-6 py-4 text-left text-sm"
                >
                  <span className="truncate font-mono text-xs">{r.source}</span>
                  <span className="truncate">{r.type}</span>
                  <span className="truncate text-muted-foreground">{r.brand ?? "Not identified"}</span>
                  <span className={`flex items-center gap-1.5 ${verdictTone(r.verdict)}`}>
                    <span className={`h-2 w-2 shrink-0 rounded-full ${verdictDot(r.verdict)}`} />
                    {r.verdict}
                  </span>
                  <span>{r.scans}</span>
                  <span className="text-muted-foreground">{r.lastSeen ? relativeTime(new Date(r.lastSeen).toISOString()) : "—"}</span>
                  <span className="text-xs">View source →</span>
                </button>
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
            aria-label={`Source investigation: ${active.source}`}
            className="absolute inset-y-0 right-0 flex w-full max-w-md flex-col gap-6 overflow-y-auto border-l border-border bg-card p-6"
          >
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <p className={`flex items-center gap-2 text-2xl font-semibold ${verdictTone(active.verdict)}`}>
                  {active.verdict}
                </p>
                <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{active.source}</p>
              </div>
              <button
                type="button"
                onClick={() => setSelected(null)}
                aria-label="Close source investigation"
                className="cursor-pointer rounded-[3px] border border-border p-2"
              >
                <X size={16} />
              </button>
            </div>

            <dl className="space-y-1.5 text-sm">
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">Source type</dt>
                <dd>{active.type}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">Associated brand</dt>
                <dd>{active.brand ?? "Not identified"}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">Related scans</dt>
                <dd>{active.scans}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">First observed</dt>
                <dd>{active.firstSeen ? shortDate(new Date(active.firstSeen).toISOString()) : "—"}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">Last observed</dt>
                <dd>{active.lastSeen ? shortDate(new Date(active.lastSeen).toISOString()) : "—"}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted-foreground">Highest risk score</dt>
                <dd>{active.score}</dd>
              </div>
            </dl>

            <div>
              <p className="text-sm text-muted-foreground">Detection evidence</p>
              {active.evidence.length === 0 ? (
                <p className="mt-2 text-sm text-muted-foreground">No direct evidence recorded for this source.</p>
              ) : (
                <ul className="mt-2 flex flex-wrap gap-2">
                  {active.evidence.map((reason) => (
                    <li key={reason} className="w-fit rounded-[3px] border border-border bg-secondary/30 px-3 py-2 text-sm">
                      {reason}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div>
              <p className="text-sm text-muted-foreground">Related scan reports</p>
              <ul className="mt-2 space-y-2">
                {active.reports.map((rep) => (
                  <li key={rep.id} className="flex items-center gap-2 text-sm">
                    <span className={verdictTone(rep.verdict)}>{rep.verdict}</span>
                    <span className="min-w-0 flex-1 truncate">{rep.filename}</span>
                    <span className="shrink-0 text-xs text-muted-foreground">{relativeTime(rep.t)}</span>
                    <button
                      type="button"
                      onClick={() => setViewId(rep.id)}
                      className="shrink-0 cursor-pointer text-xs text-primary underline"
                    >
                      View
                    </button>
                  </li>
                ))}
              </ul>
            </div>

            <div className="mt-auto space-y-2 border-t border-border pt-4">
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={copySource}
                  className="cursor-pointer rounded-[3px] border border-border px-4 py-2 text-sm"
                >
                  {copied ? "Copied" : "Copy source"}
                </button>
                <a href="#/indicators" className="rounded-[3px] border border-border px-4 py-2 text-sm">
                  Open in Indicators
                </a>
              </div>
            </div>
          </aside>
        </div>
      )}

      <ScanDetailModal id={viewId} onClose={() => setViewId(null)} />
    </WorkspaceShell>
  );
}
