import { describe, it, expect } from "vitest";
import { analyze, verdictFor, lookalike } from "./engine";
import { SAMPLES } from "./samples";

describe("engine", () => {
  it("uses 70/40 thresholds", () => {
    expect(verdictFor(70)).toBe("Malicious");
    expect(verdictFor(69)).toBe("Suspicious");
    expect(verdictFor(40)).toBe("Suspicious");
    expect(verdictFor(39)).toBe("Verified");
  });
  it("catches lookalikes", () => {
    expect(lookalike("paypai.com")).toBe("paypal.com");
    expect(lookalike("chase-secure.co")).toBe("chase.com");
    expect(lookalike("chase.com")).toBeNull();
  });
  it("verdicts samples", () => {
    expect(analyze(SAMPLES.clean).verdict).toBe("Verified");
    expect(analyze(SAMPLES.phishing).verdict).toBe("Malicious");
  });
});
