import type { NlVerdict } from "@/lib/api";

/**
 * The LLM's plain-English verdict: what was found, why it matters, what to do.
 *
 * The verdict and score come from the deterministic engine, and the backend
 * feeds that evidence to Gemini purely to explain it. So this always restates
 * the engine's decision — it never contradicts or softens it. Renders nothing
 * when a scan has no `nl` (older reports, or a provider that returned none).
 *
 * Unlike the rest of the dashboard this card uses a fixed light palette rather
 * than the semantic tokens, so it stays legible and consistent in dark theme.
 */
export function NlVerdictCard({ nl }: { nl?: NlVerdict | undefined }) {
  if (!nl) return null;
  return (
    <div className="mt-4 rounded-[3px] border border-[#CDE7DE] bg-[#F9FFFD] p-4">
      <p className="text-sm font-semibold text-[#0B1F1A]">{nl.headline}</p>
      <p className="mt-2 text-sm text-[#44655B]">{nl.summary}</p>
      {nl.action && (
        <p className="mt-3 text-sm text-[#0B1F1A]">
          <span className="text-[#44655B]">What to do: </span>
          {nl.action}
        </p>
      )}
    </div>
  );
}
