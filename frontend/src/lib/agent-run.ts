import type { AgentRunEvent } from "@/lib/api";

interface Phase {
  step: string;
  label: string;
  state: "active" | "done";
  detail?: string | undefined;
}

interface Attempt {
  provider: string;
  model: string;
  state: "trying" | "ok" | "failed";
  error?: string | undefined;
}

/** One line of a generated script, tagged with the variant that produced it. */
export interface ScriptLine {
  profile: string;
  line: string;
}

/**
 * What the agent-run view draws, accumulated from the scan's event stream.
 *
 * Script lines are collected as fast as the server sends them — the server does
 * not pace them — and the modal reveals them at a readable speed itself. So the
 * animation can be slowed down, or still be running when the verdict lands,
 * without ever holding up the scan.
 */
export interface AgentRunState {
  phases: Phase[];
  profiles: string[];
  lines: ScriptLine[];
  attempts: Attempt[];
}

export const emptyRun: AgentRunState = { phases: [], profiles: [], lines: [], attempts: [] };

/**
 * Fold one streamed event into the run state. Kept out of the component so the
 * scan panel can own the request while the modal only renders the result.
 */
export function reduceRun(prev: AgentRunState, event: AgentRunEvent): AgentRunState {
  switch (event.type) {
    case "status":
      // A step reports twice (active, then done); replace rather than append.
      return {
        ...prev,
        phases: [
          ...prev.phases.filter((p) => p.step !== event.step),
          { step: event.step, label: event.label, state: event.state, detail: event.detail },
        ],
      };
    case "script":
      // Deep scans send two scripts; keep the order so the panes can be labelled.
      return prev.profiles.includes(event.profile)
        ? prev
        : { ...prev, profiles: [...prev.profiles, event.profile] };
    case "script_line":
      return { ...prev, lines: [...prev.lines, { profile: event.profile, line: event.line }] };
    case "llm":
      return {
        ...prev,
        attempts: [
          ...prev.attempts,
          { provider: event.provider, model: event.model, state: event.state, error: event.error },
        ],
      };
  }
}
