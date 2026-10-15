import { useRef, useState } from "react";
import {
  AlertTriangle,
  FileUp,
  Mail,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";

import { reportUrl, scanWithProgress, type ScanResult, type Verdict } from "@/lib/api";
import { verdictTone } from "@/lib/threat-stats";

const VERDICT_ICON: Record<Verdict, typeof ShieldCheck> = {
  Verified: ShieldCheck,
  Suspicious: AlertTriangle,
  Malicious: ShieldAlert,
};

const VERDICT_BAR: Record<Verdict, string> = {
  Verified: "bg-success",
  Suspicious: "bg-warning",
  Malicious: "bg-destructive",
};

export function ScanPanel({ onScanned }: { onScanned: () => void }) {
  const [tab, setTab] = useState<"file" | "email">("file");
  const [file, setFile] = useState<File | null>(null);
  const [emailText, setEmailText] = useState("");
  const [deep, setDeep] = useState(false);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [dragging, setDragging] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  const ready = tab === "file" ? !!file : emailText.trim().length > 0;

  async function submit() {
    if (!ready || busy) return;
    setBusy(true);
    setError(null);
    setProgress(tab === "file" ? 0 : null);
    try {
      const payload = tab === "file" ? { file } : { emailText, filename: "pasted-email.eml" };
      const res = await scanWithProgress(payload, { deep }, (p) => setProgress(p));
      setResult(res);
      onScanned();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      setProgress(null);
    }
  }

  function pickFile(next: File | null) {
    setFile(next);
    setError(null);
  }

  const VerdictIcon = result ? VERDICT_ICON[result.verdict] : ShieldCheck;

  return (
    <section className="panel p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-2xl">Scan a suspicious file or email</h2>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            The agent writes its own Python and runs it in an isolated micro-VM with egress blocked.
            Nothing here is executed, and only hashes plus the generated code are stored.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setDeep((v) => !v)}
          aria-pressed={deep}
          className="flex cursor-pointer items-center gap-2 rounded-[3px] border border-border px-3 py-2 text-sm text-muted-foreground"
        >
          <span
            aria-hidden="true"
            className={`relative h-5 w-9 shrink-0 rounded-[3px] border transition-colors duration-300 ${deep ? "border-primary bg-primary" : "border-border bg-secondary"}`}
          >
            <span
              className={`absolute left-[1px] top-1/2 h-4 w-4 -translate-y-1/2 rounded-[3px] transition-all duration-300 ${deep ? "translate-x-[16px] bg-primary-foreground" : "translate-x-0 bg-muted-foreground"}`}
            />
          </span>
          Deep scan {deep ? "· on" : "· off"}
        </button>
      </div>

      <div className="mt-5 flex w-fit gap-1 rounded-[3px] border border-border bg-secondary p-1 text-sm">
        {(
          [
            ["file", "Suspicious file", FileUp],
            ["email", "Bank email", Mail],
          ] as const
        ).map(([key, label, Icon]) => (
          <button
            key={key}
            type="button"
            onClick={() => setTab(key)}
            className={`flex cursor-pointer items-center gap-2 rounded-[3px] px-4 py-2 ${tab === key ? "bg-card text-foreground" : "text-muted-foreground"}`}
          >
            <Icon size={15} /> {label}
          </button>
        ))}
      </div>

      {tab === "file" ? (
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            pickFile(e.dataTransfer.files?.[0] ?? null);
          }}
          className={`mt-4 cursor-pointer rounded-[3px] border border-dashed p-8 text-center ${dragging ? "border-primary bg-secondary/60" : "border-border bg-secondary/30"}`}
        >
          <FileUp size={22} className="mx-auto text-primary" />
          {file ? (
            <>
              <p className="mt-3 text-sm">{file.name}</p>
              <p className="text-xs text-muted-foreground">{(file.size / 1024).toFixed(1)} KB</p>
              <button
                type="button"
                onClick={() => pickFile(null)}
                className="mt-3 text-xs text-muted-foreground"
              >
                <X size={12} className="mr-1 inline" /> remove
              </button>
            </>
          ) : (
            <>
              <p className="mt-3 text-sm">
                Drop a file here, or{" "}
                <button
                  type="button"
                  onClick={() => input.current?.click()}
                  className="text-primary underline"
                >
                  browse
                </button>
              </p>
              <p className="mt-1 text-xs text-muted-foreground">
                .eml, .msg, .html, .txt — up to 8 MB
              </p>
            </>
          )}
          <input
            ref={input}
            type="file"
            className="hidden"
            onChange={(e) => pickFile(e.target.files?.[0] ?? null)}
          />
        </div>
      ) : (
        <div className="mt-4">
          <textarea
            value={emailText}
            onChange={(e) => setEmailText(e.target.value)}
            placeholder={
              'Paste the raw message (headers and all) — e.g. From: "Chase Bank" <alerts@chase-secure.co>'
            }
            className="h-44 w-full resize-y rounded-[3px] border border-border bg-secondary/30 p-4 font-mono text-xs text-foreground outline-none placeholder:text-muted-foreground focus:border-primary"
          />
        </div>
      )}

      <div className="mt-5 flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={submit}
          disabled={!ready || busy}
          className="flex cursor-pointer items-center rounded-[3px] bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-50"
        >
          {busy
            ? deep
              ? "Two sandboxes running…"
              : "Agent scanning…"
            : deep
              ? "Deep scan"
              : "Get verdict"}
        </button>
        {error && <span className="text-sm text-destructive">{error}</span>}
      </div>

      {progress !== null && (
        <div className="mt-5" role="status" aria-label={`Upload progress ${progress}%`}>
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span className="truncate">Uploading {file?.name ?? "file"}…</span>
            <span>{progress}%</span>
          </div>
          <div className="mt-2 h-2 w-full overflow-hidden rounded-[3px] bg-secondary">
            <div
              className="h-full bg-primary transition-all duration-200"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {result && (
        <div className="mt-6 grid gap-6 xl:grid-cols-[1fr_1fr]">
          <div className="rounded-[3px] border border-border bg-secondary/30 p-5">
            <div className="flex items-center gap-4">
              <VerdictIcon size={30} className={verdictTone(result.verdict)} />
              <div>
                <p className={`text-2xl font-semibold ${verdictTone(result.verdict)}`}>
                  {result.verdict}
                </p>
                <p className="text-xs text-muted-foreground">
                  score {result.score} · {result.kind} ·{" "}
                  {(result.size ?? 0) / 1024 > 0
                    ? `${((result.size ?? 0) / 1024).toFixed(1)} KB`
                    : "—"}
                </p>
              </div>
              <a
                href={reportUrl(result.id)}
                target="_blank"
                rel="noreferrer"
                className="ml-auto rounded-[3px] border border-border px-3 py-2 text-xs"
              >
                Share report
              </a>
            </div>

            <div className="mt-4 h-2 w-full overflow-hidden rounded-full bg-secondary">
              <div
                className={`h-full ${VERDICT_BAR[result.verdict]}`}
                style={{ width: `${Math.min(100, Math.max(3, result.score))}%` }}
              />
            </div>

            {result.mode && (
              <p className="mt-3 text-xs text-muted-foreground">run mode: {result.mode}</p>
            )}

            {result.runs && (
              <div className="mt-4 space-y-2 text-xs">
                {result.runs.map((run) => (
                  <div
                    key={run.profile}
                    className="flex items-center justify-between rounded-[3px] border border-border px-3 py-2"
                  >
                    <span className="text-muted-foreground">{run.profile} variant</span>
                    <span className={verdictTone(run.verdict)}>
                      {run.verdict} · {run.score}
                    </span>
                  </div>
                ))}
                <p className="text-muted-foreground">
                  {result.agreement
                    ? "Both variants agree — harsher verdict wins."
                    : "Variants disagree — the harsher verdict wins."}
                </p>
              </div>
            )}

            <ul className="mt-4 space-y-2">
              {result.reasons.map((reason) => (
                <li
                  key={reason}
                  className="rounded-[3px] border border-border bg-card px-3 py-2 text-sm"
                >
                  {reason}
                </li>
              ))}
            </ul>

            {result.iocs.domains.length + result.iocs.urls.length > 0 && (
              <div className="mt-4 flex flex-wrap gap-2">
                {[result.iocs.sha256, ...result.iocs.domains, ...result.iocs.urls]
                  .filter(Boolean)
                  .map((ioc) => (
                    <span
                      key={ioc}
                      className="rounded-[3px] border border-border bg-secondary px-2 py-1 font-mono text-xs"
                    >
                      {ioc}
                    </span>
                  ))}
              </div>
            )}
          </div>

          {result.agent_code && (
            <div className="overflow-hidden rounded-[3px] border border-border">
              <div className="flex items-center gap-2 border-b border-border bg-secondary px-4 py-3 text-xs text-muted-foreground">
                <span className="h-2.5 w-2.5 rounded-full bg-destructive" />
                <span className="h-2.5 w-2.5 rounded-full bg-warning" />
                <span className="h-2.5 w-2.5 rounded-full bg-success" />
                <span className="ml-2 font-mono">scan.py — written and run by the agent</span>
              </div>
              <pre className="chart-bg max-h-96 overflow-auto p-4 font-mono text-xs leading-relaxed text-foreground">
                {result.agent_code}
              </pre>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
