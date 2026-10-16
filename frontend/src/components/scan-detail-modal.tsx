import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Check, Link2, X } from "lucide-react";

import { NlVerdictCard } from "@/components/nl-verdict";
import { fetchReport, reportUrl } from "@/lib/api";
import { relativeTime, shortDate, verdictTone } from "@/lib/threat-stats";

/**
 * Full scan details in a modal, so "View" shows the report in place instead of
 * opening the public `/v/:id` page in a new tab. The row already carries the
 * verdict, so we fetch the heavy parts (plain-English verdict, reasons,
 * indicators, deep-scan runs, agent code) on open.
 */
export function ScanDetailModal({ id, onClose }: { id: string | null; onClose: () => void }) {
  const [showCode, setShowCode] = useState(false);
  const [copied, setCopied] = useState(false);

  const report = useQuery({
    queryKey: ["report", id],
    queryFn: () => fetchReport(id as string),
    enabled: !!id,
  });

  useEffect(() => {
    if (!id) return;
    setShowCode(false);
    setCopied(false);
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [id, onClose]);

  if (!id) return null;

  const r = report.data;
  const reasons = r?.reasons ?? [];
  const iocs = r?.iocs;
  const runs = r?.runs;

  async function copyLink() {
    try {
      await navigator.clipboard.writeText(
        new URL(reportUrl(id as string), window.location.origin).href,
      );
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard blocked — nothing useful to show */
    }
  }

  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} aria-hidden="true" />
      <div className="absolute inset-0 grid place-items-center p-4">
        <div
          role="dialog"
          aria-modal="true"
          aria-label={`Scan details: ${r?.filename ?? id}`}
          className="flex max-h-full w-full max-w-2xl flex-col gap-6 overflow-y-auto rounded-[3px] border border-border bg-card p-6"
        >
          {report.isPending && <p className="text-sm text-muted-foreground">Loading report…</p>}

          {report.isError && (
            <p className="text-sm text-destructive">
              Could not load report ({(report.error as Error).message}).
            </p>
          )}

          {r && (
            <>
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-xs uppercase tracking-wide text-muted-foreground">
                    Scan report · {r.id}
                  </p>
                  <p className="mt-1 break-words text-2xl font-semibold">{r.filename ?? "—"}</p>
                  <p
                    className={`mt-2 flex items-center gap-2 text-lg font-semibold ${verdictTone(r.verdict)}`}
                  >
                    {r.verdict}
                    <span className="text-sm font-normal text-muted-foreground">
                      Risk score {r.score}
                    </span>
                  </p>
                </div>
                <button
                  type="button"
                  onClick={onClose}
                  aria-label="Close scan details"
                  className="shrink-0 cursor-pointer rounded-[3px] border border-border p-2"
                >
                  <X size={16} />
                </button>
              </div>

              <NlVerdictCard nl={r.nl} />

              <dl className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-sm">
                <div className="flex justify-between gap-4">
                  <dt className="text-muted-foreground">Analysis mode</dt>
                  <dd>{r.deep ? "Deep scan" : "Standard"}</dd>
                </div>
                <div className="flex justify-between gap-4">
                  <dt className="text-muted-foreground">Scanned</dt>
                  <dd>{r.t ? `${shortDate(r.t)} · ${relativeTime(r.t)}` : "—"}</dd>
                </div>
                <div className="flex justify-between gap-4">
                  <dt className="text-muted-foreground">Execution mode</dt>
                  <dd className="truncate">{r.mode ?? "—"}</dd>
                </div>
                <div className="flex justify-between gap-4">
                  <dt className="text-muted-foreground">Report ID</dt>
                  <dd className="truncate font-mono text-xs">{r.id}</dd>
                </div>
              </dl>

              <div>
                <p className="text-sm text-muted-foreground">Why this was flagged</p>
                {reasons.length === 0 ? (
                  <p className="mt-2 text-sm text-muted-foreground">No reasons recorded.</p>
                ) : (
                  <ul className="mt-2 flex flex-wrap gap-2">
                    {reasons.map((reason) => (
                      <li
                        key={reason}
                        className="w-fit rounded-[3px] border border-border bg-secondary/30 px-3 py-2 text-sm"
                      >
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
                    {[iocs.sha256, ...iocs.domains, ...iocs.urls].filter(Boolean).map((ioc) => (
                      <span
                        key={ioc}
                        className="max-w-full truncate rounded-[3px] border border-border bg-secondary px-2 py-1 font-mono text-xs"
                      >
                        {ioc}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {runs && runs.length > 0 && (
                <div>
                  <p className="text-sm text-muted-foreground">Deep scan comparison</p>
                  <ul className="mt-2 space-y-2 text-sm">
                    {runs.map((run) => (
                      <li
                        key={run.profile}
                        className="flex items-center justify-between rounded-[3px] border border-border px-3 py-2"
                      >
                        <span className="text-muted-foreground">{run.profile} variant</span>
                        <span className={verdictTone(run.verdict)}>
                          {run.verdict} · {run.score}
                        </span>
                      </li>
                    ))}
                  </ul>
                  <p className="mt-2 text-xs text-muted-foreground">
                    {r.agreement
                      ? "Both variants agree — harsher verdict wins."
                      : "Variants disagree — the harsher verdict wins."}
                  </p>
                </div>
              )}

              {r.agent_code ? (
                <div>
                  <div className="flex items-center justify-between">
                    <p className="text-sm text-muted-foreground">Agent analysis</p>
                    <button
                      type="button"
                      onClick={() => setShowCode((v) => !v)}
                      aria-expanded={showCode}
                      className="cursor-pointer rounded-[3px] border border-border px-3 py-1.5 text-xs"
                    >
                      {showCode ? "Hide code" : "Show code"}
                    </button>
                  </div>
                  {showCode && (
                    <pre className="chart-bg mt-2 max-h-96 overflow-auto rounded-[3px] border border-border p-4 font-mono text-xs leading-relaxed text-foreground">
                      {r.agent_code}
                    </pre>
                  )}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">
                  No agent code recorded for this report.
                </p>
              )}

              <div className="flex flex-wrap gap-2 border-t border-border pt-4">
                <button
                  type="button"
                  onClick={copyLink}
                  className="flex cursor-pointer items-center gap-2 rounded-[3px] border border-border px-4 py-2 text-sm"
                >
                  {copied ? <Check size={14} /> : <Link2 size={14} />}
                  {copied ? "Copied" : "Copy report link"}
                </button>
                <button
                  type="button"
                  onClick={onClose}
                  className="cursor-pointer rounded-[3px] bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground"
                >
                  Close
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
