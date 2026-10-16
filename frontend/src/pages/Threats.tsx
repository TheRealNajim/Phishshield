import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  CalendarCheck, RefreshCw, Search, ShieldAlert, TriangleAlert, X,
} from "lucide-react";

import { WorkspaceShell } from "@/components/workspace-shell";
import { FilterDropdown } from "@/components/filter-dropdown";
import { deleteReport, fetchHistory, reportUrl } from "@/lib/api";
import type { ScanSummary, Verdict } from "@/lib/api";
import {
  primaryCategory,
  relativeTime,
  shortDate,
  verdictTone,
} from "@/lib/threat-stats";
import { useRoute } from "@/lib/route";

type QueueTab = "all" | Verdict;
const TABS: { id: QueueTab; label: string }[] = [
  { id: "all", label: "All" },
  { id: "Malicious", label: "Malicious" },
  { id: "Suspicious", label: "Suspicious" },
  { id: "Verified", label: "Low risk" },
];

const PAGE_SIZE = 8;

const KIND_OPTIONS = [
  { value: "all", label: "Email + files" },
  { value: "email", label: "Email" },
  { value: "file", label: "File" },
] as const;

function isVerdict(v: string | null): v is Verdict {
  return v === "Verified" || v === "Suspicious" || v === "Malicious";
}

export function Threats() {
  const history = useQuery({ queryKey: ["history"], queryFn: fetchHistory, refetchInterval: 30_000 });
  const scans = history.data ?? [];
  const { params } = useRoute();

  const [tab, setTab] = useState<QueueTab>(() => {
    const initial = params.get("verdict");
    return isVerdict(initial) ? initial : "all";
  });
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<"all" | "email" | "file">("all");
  const [visible, setVisible] = useState(PAGE_SIZE);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [copied, setCopied] = useState(false);
  const [drawerError, setDrawerError] = useState<string | null>(null);

  useEffect(() => {
    setVisible(PAGE_SIZE);
  }, [tab, query, kind]);

  const sorted = useMemo(
    () => [...scans].sort((a, b) => Date.parse(b.t) - Date.parse(a.t)),
    [scans],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return sorted.filter((s) => {
      if (tab !== "all" && s.verdict !== tab) return false;
      if (kind !== "all" && s.kind !== kind) return false;
      if (!q) return true;
      const haystack = [
        s.filename,
        s.id,
        (s.reasons ?? []).join(" "),
        ...(s.iocs.domains ?? []),
        ...(s.iocs.urls ?? []),
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [sorted, tab, kind, query]);

  const malicious = sorted.filter((s) => s.verdict === "Malicious").length;
  const suspicious = sorted.filter((s) => s.verdict === "Suspicious").length;
  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  const detectedToday = sorted.filter((s) => {
    const t = Date.parse(s.t);
    return Number.isFinite(t) && t >= todayStart.getTime();
  }).length;

  const shown = filtered.slice(0, visible);
  const selected: ScanSummary | undefined = scans.find((s) => s.id === selectedId) ?? undefined;

  function openInvestigation(id: string) {
    setSelectedId(id);
    setConfirmingDelete(false);
    setCopied(false);
    setDrawerError(null);
  }

  useEffect(() => {
    if (!selected) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setSelectedId(null);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [selected]);

  async function copyLink() {
    if (!selected) return;
    try {
      await navigator.clipboard.writeText(new URL(reportUrl(selected.id), window.location.origin).href);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setDrawerError("Copy unavailable in this browser.");
    }
  }

  async function remove() {
    if (!selected) return;
    setDeleting(true);
    setDrawerError(null);
    try {
      await deleteReport(selected.id);
      setSelectedId(null);
      setConfirmingDelete(false);
      await history.refetch();
    } catch (e) {
      setDrawerError(e instanceof Error ? e.message : String(e));
    } finally {
      setDeleting(false);
    }
  }

  const SUMMARY = [
    { title: "Malicious", value: malicious, note: "High-priority findings", icon: ShieldAlert },
    { title: "Suspicious", value: suspicious, note: "Require review", icon: TriangleAlert },
    { title: "Detected today", value: detectedToday, note: "Across analyzed items", icon: CalendarCheck },
  ];

  return (
    <WorkspaceShell
      section="Threats"
      actions={
        <button onClick={() => history.refetch()} className="flex cursor-pointer items-center gap-2 rounded-[3px] border border-border px-3 py-2 text-sm text-on-chrome">
          <RefreshCw size={16} className={`text-primary ${history.isFetching ? "animate-spin" : ""}`} /> Refresh Data
        </button>
      }
    >
      <div className="space-y-8 p-6">
        <section className="grid grid-cols-2 gap-5 xl:grid-cols-3">
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
            {TABS.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setTab(t.id)}
                aria-pressed={tab === t.id}
                className={`cursor-pointer rounded-[3px] px-4 py-2 ${tab === t.id ? "bg-card text-foreground" : "text-muted-foreground"}`}
              >
                {t.label}
              </button>
            ))}
          </div>
          <label className="flex w-56 cursor-text items-center gap-2 rounded-[3px] border border-border bg-secondary px-4 py-2.5 text-sm text-muted-foreground">
            <Search size={16} />
            <input
              placeholder="Search threats"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full bg-transparent text-foreground outline-none placeholder:text-muted-foreground"
            />
          </label>
          <FilterDropdown label="Item type" value={kind} options={KIND_OPTIONS} onChange={setKind} />
        </div>

        <section className="space-y-3">
          {history.isPending && (
            <div className="row-panel px-6 py-5 text-sm text-muted-foreground">Loading threat queue…</div>
          )}
          {history.isError && (
            <div className="row-panel px-6 py-5 text-sm text-destructive">
              Could not load threats: {(history.error as Error).message}
            </div>
          )}
          {!history.isPending && !history.isError && filtered.length === 0 && (
            <div className="row-panel px-6 py-5 text-sm text-muted-foreground">
              No threats match these filters.
            </div>
          )}
          {shown.map((r) => {
            const domain = r.iocs.domains[0];
            return (
              <button
                key={r.id}
                type="button"
                onClick={() => openInvestigation(r.id)}
                className="row-panel grid w-full cursor-pointer grid-cols-[auto_1fr_auto] items-center gap-x-4 gap-y-1 px-6 py-4 text-left text-sm"
              >
                <span className={`flex items-center gap-1.5 ${verdictTone(r.verdict)}`}>
                  <span className={`h-2 w-2 rounded-full ${r.verdict === "Malicious" ? "bg-destructive" : r.verdict === "Suspicious" ? "bg-warning" : "bg-success"}`} />
                  {r.verdict}
                </span>
                <span className="min-w-0">
                  <span className="block truncate">{r.filename}</span>
                  <span className="block truncate text-xs text-muted-foreground">
                    {domain ?? (r.kind === "email" ? "Email threat" : "File")} ·{" "}
                    <span>{primaryCategory(r)}</span>
                  </span>
                </span>
                <span className="flex items-center gap-4">
                  <span className="text-xs text-muted-foreground">Risk score {r.score}</span>
                  <span className="text-xs text-muted-foreground">{relativeTime(r.t)}</span>
                  <span className="text-xs">Inspect →</span>
                </span>
              </button>
            );
          })}
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

      {selected && (
        <div className="fixed inset-0 z-30">
          <div className="absolute inset-0 bg-black/60" onClick={() => setSelectedId(null)} aria-hidden="true" />
          <aside
            role="dialog"
            aria-modal="true"
            aria-label={`Investigation: ${selected.filename}`}
            className="absolute inset-y-0 right-0 flex w-full max-w-md flex-col gap-6 overflow-y-auto border-l border-border bg-card p-6"
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className={`flex items-center gap-2 text-2xl font-semibold ${verdictTone(selected.verdict)}`}>
                  {selected.verdict}
                </p>
                <p className="mt-1 text-xs text-muted-foreground">Risk score {selected.score}</p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedId(null)}
                aria-label="Close investigation"
                className="cursor-pointer rounded-[3px] border border-border p-2"
              >
                <X size={16} />
              </button>
            </div>

            <div>
              <p className="text-sm text-muted-foreground">Threat summary</p>
              <p className="mt-1 break-words font-medium">{selected.filename}</p>
              <dl className="mt-3 space-y-1.5 text-sm">
                <div className="flex justify-between gap-4">
                  <dt className="text-muted-foreground">Detected</dt>
                  <dd>{shortDate(selected.t)} · {relativeTime(selected.t)}</dd>
                </div>
                <div className="flex justify-between gap-4">
                  <dt className="text-muted-foreground">Type</dt>
                  <dd>{selected.kind === "email" ? "Email" : "File"}</dd>
                </div>
                <div className="flex justify-between gap-4">
                  <dt className="text-muted-foreground">Analysis mode</dt>
                  <dd>{selected.mode ?? "—"}</dd>
                </div>
                <div className="flex justify-between gap-4">
                  <dt className="text-muted-foreground">Report</dt>
                  <dd className="font-mono text-xs">{selected.id}</dd>
                </div>
              </dl>
            </div>

            <div>
              <p className="text-sm text-muted-foreground">Why it was flagged</p>
              {selected.reasons.length === 0 ? (
                <p className="mt-2 text-sm text-muted-foreground">No reasons recorded.</p>
              ) : (
                <ul className="mt-2 flex flex-wrap gap-2">
                  {selected.reasons.map((reason) => (
                    <li key={reason} className="w-fit rounded-[3px] border border-border bg-secondary/30 px-3 py-2 text-sm">
                      {reason}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div>
              <p className="text-sm text-muted-foreground">Related indicators</p>
              {selected.iocs.domains.length + selected.iocs.urls.length + (selected.iocs.sha256 ? 1 : 0) === 0 ? (
                <p className="mt-2 text-sm text-muted-foreground">No indicators extracted.</p>
              ) : (
                <div className="mt-2 flex flex-wrap gap-2">
                  {[selected.iocs.sha256, ...selected.iocs.domains, ...selected.iocs.urls]
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

            <div className="mt-auto space-y-2 border-t border-border pt-4">
              <p className="text-sm text-muted-foreground">Investigation actions</p>
              <div className="flex flex-wrap gap-2">
                <a
                  href={reportUrl(selected.id)}
                  target="_blank"
                  rel="noreferrer"
                  className="rounded-[3px] bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground"
                >
                  Open full report
                </a>
                <button
                  type="button"
                  onClick={copyLink}
                  className="cursor-pointer rounded-[3px] border border-border px-4 py-2 text-sm"
                >
                  {copied ? "Copied" : "Copy report link"}
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
