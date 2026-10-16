import { useEffect, useRef, useState } from "react";
import { Check, ChevronUp, Loader2, Terminal } from "lucide-react";

import type { AgentRunState } from "@/lib/agent-run";

/**
 * How fast the received script is typed out, in milliseconds per line. Deliberately
 * far slower than the network so the code can be followed as it appears; the scan is
 * never held back by it, so a fast verdict can cut the reveal short.
 *
 * Tune it without a code change via VITE_SCRIPT_REVEAL_MS (milliseconds per line).
 */
const configuredRevealMs = Number(import.meta.env?.["VITE_SCRIPT_REVEAL_MS"] as string | undefined);
const LINE_REVEAL_MS =
  Number.isFinite(configuredRevealMs) && configuredRevealMs > 0 ? configuredRevealMs : 150;

/**
 * The live view of the agent working: the phases it moves through, the Python
 * it writes for this job, and each model it asks for the plain-English verdict.
 *
 * Purely a progress surface — the scan panel owns the request and mounts this
 * while it is in flight, then swaps it for the report. "Hide" collapses it to a
 * badge so a slow provider does not lock the page; the scan keeps running.
 *
 * Like NlVerdictCard this uses a fixed dark palette rather than the semantic
 * tokens, so the terminal reads the same in light and dark themes.
 */
export function AgentRunModal({
  run,
  hidden,
  onHide,
  onShow,
}: {
  run: AgentRunState;
  hidden: boolean;
  onHide: () => void;
  onShow: () => void;
}) {
  const [elapsed, setElapsed] = useState(0);
  const [revealed, setRevealed] = useState(0);
  const codeRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    const id = window.setInterval(() => setElapsed((s) => s + 1), 1000);
    return () => window.clearInterval(id);
  }, []);

  // Type the received lines out one at a time, however fast they arrived.
  useEffect(() => {
    if (revealed >= run.lines.length) return;
    const id = window.setTimeout(() => setRevealed((n) => n + 1), LINE_REVEAL_MS);
    return () => window.clearTimeout(id);
  }, [revealed, run.lines.length]);

  // Follow the script as it is written.
  useEffect(() => {
    const el = codeRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [revealed]);

  if (hidden) {
    return (
      <button
        type="button"
        onClick={onShow}
        className="fixed bottom-4 right-4 z-50 flex cursor-pointer items-center gap-2 rounded-[3px] border border-[#1E3B33] bg-[#0B1F1A] px-4 py-3 text-sm text-[#D7F5E9]"
      >
        <Loader2 size={14} className="animate-spin text-[#4ADE80]" />
        Agent working… {elapsed}s
        <ChevronUp size={14} />
      </button>
    );
  }

  const multi = run.profiles.length > 1;
  const typing = revealed < run.lines.length;
  const active = run.phases.length === 0 || run.phases.some((p) => p.state === "active");

  // Group the revealed lines by variant so a second script gets its own heading.
  const groups: { profile: string; lines: string[] }[] = [];
  for (const row of run.lines.slice(0, revealed)) {
    const last = groups[groups.length - 1];
    if (last && last.profile === row.profile) last.lines.push(row.line);
    else groups.push({ profile: row.profile, lines: [row.line] });
  }

  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/70" aria-hidden="true" />
      <div className="absolute inset-0 grid place-items-center p-4">
        <div
          role="dialog"
          aria-modal="true"
          aria-label="The agent is analysing your message"
          className="flex max-h-full w-full max-w-3xl flex-col overflow-hidden rounded-[3px] border border-[#1E3B33] bg-[#0B1F1A] text-[#D7F5E9]"
        >
          <div className="flex items-center gap-2 border-b border-[#1E3B33] px-4 py-3 text-xs text-[#7FA79A]">
            <Terminal size={14} />
            <span className="truncate font-mono">scan.py — being written by the agent</span>
            <span className="ml-auto shrink-0 tabular-nums">{elapsed}s</span>
            <button
              type="button"
              onClick={onHide}
              className="shrink-0 cursor-pointer rounded-[3px] border border-[#1E3B33] px-2 py-0.5 text-[#D7F5E9]"
            >
              Hide
            </button>
          </div>

          <ul className="space-y-1.5 border-b border-[#1E3B33] px-5 py-4 text-sm">
            {run.phases.length === 0 && <li className="text-[#7FA79A]">Contacting the agent…</li>}
            {run.phases.map((phase) => (
              <li key={phase.step} className="flex items-center gap-2">
                {phase.state === "done" ? (
                  <Check size={14} className="shrink-0 text-[#4ADE80]" />
                ) : (
                  <Loader2 size={14} className="shrink-0 animate-spin text-[#4ADE80]" />
                )}
                <span className={phase.state === "done" ? "text-[#7FA79A]" : undefined}>
                  {phase.label}
                </span>
                {phase.detail && (
                  <span className="ml-auto truncate font-mono text-xs text-[#7FA79A]">
                    {phase.detail}
                  </span>
                )}
              </li>
            ))}
          </ul>

          <pre
            ref={codeRef}
            className="max-h-[45vh] min-h-[12rem] flex-1 overflow-auto px-5 py-4 font-mono text-xs leading-relaxed text-[#D7F5E9]"
          >
            {groups.map((group, i) => (
              <span key={`${group.profile}-${i}`}>
                {multi && (
                  <span className="block text-[#7FA79A]"># --- {group.profile} variant ---</span>
                )}
                {group.lines.join("\n") + "\n"}
              </span>
            ))}
            {(typing || active) && <span className="animate-pulse">▊</span>}
          </pre>

          {run.attempts.length > 0 && (
            <ul className="max-h-28 shrink-0 space-y-1 overflow-auto border-t border-[#1E3B33] px-5 py-3 font-mono text-[11px] text-[#7FA79A]">
              {run.attempts.map((attempt, i) => (
                <li key={`${attempt.provider}-${attempt.model}-${i}`} className="truncate">
                  {attempt.provider}/{attempt.model} ·{" "}
                  {attempt.state === "trying"
                    ? "asking…"
                    : attempt.state === "ok"
                      ? "answered"
                      : `unavailable${attempt.error ? ` — ${attempt.error}` : ""}`}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
