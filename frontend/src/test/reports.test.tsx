import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "@/App";
import type { ScanSummary } from "@/lib/api";
import { stubApi } from "./mock-api";

function renderApp() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>,
  );
}

function goReports(hash = "#/reports") {
  window.location.hash = hash;
}

function openRow(filename: string) {
  const name = screen.getByText(filename);
  const row = name.closest("div");
  if (!row) throw new Error(`row for ${filename} missing`);
  fireEvent.click(within(row as HTMLElement).getByRole("button", { name: "Open" }));
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  delete (URL as unknown as Record<string, unknown>)["createObjectURL"];
  delete (URL as unknown as Record<string, unknown>)["revokeObjectURL"];
  try {
    delete (window.navigator as unknown as Record<string, unknown>)["clipboard"];
  } catch {
    /* clipboard was never stubbed */
  }
  window.location.hash = "";
  window.history.pushState({}, "", "/");
});

describe("reports archive", () => {
  it("shows KPIs, rows with IDs, scores, types and sort control", async () => {
    stubApi();
    goReports();
    renderApp();

    expect(await screen.findByText("Total reports")).toBeInTheDocument();
    expect(screen.getByText("chase-alert.eml")).toBeInTheDocument();
    expect(screen.getByText("r1")).toBeInTheDocument();
    expect(screen.getByText("200")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sort reports" })).toBeInTheDocument();
  });

  it("searches by ID, filters by verdict and sorts", async () => {
    stubApi();
    goReports();
    renderApp();

    await screen.findByText("chase-alert.eml");
    fireEvent.change(screen.getByPlaceholderText("Search reports or IDs"), {
      target: { value: "r1" },
    });
    expect(screen.queryByText("newsletter.eml")).not.toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText("Search reports or IDs"), {
      target: { value: "" },
    });

    fireEvent.click(screen.getByRole("button", { name: "Suspicious" }));
    expect(screen.getByText("No reports match these filters.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "All reports" }));

    // Default is newest first: newsletter (30 min) before chase-alert (2h).
    expect(screen.getAllByText(/\.eml/).map((e) => e.textContent)).toEqual([
      "newsletter.eml",
      "chase-alert.eml",
    ]);

    fireEvent.click(screen.getByRole("button", { name: "Sort reports" }));
    fireEvent.click(await screen.findByRole("menuitem", { name: "Oldest first" }));
    expect(screen.getAllByText(/\.eml/).map((e) => e.textContent)).toEqual([
      "chase-alert.eml",
      "newsletter.eml",
    ]);

    fireEvent.click(screen.getByRole("button", { name: "Sort reports" }));
    fireEvent.click(await screen.findByRole("menuitem", { name: "Highest score" }));
    expect(screen.getAllByText(/\.eml/).map((e) => e.textContent)).toEqual([
      "chase-alert.eml",
      "newsletter.eml",
    ]);
  });

  it("honours a deep-linked verdict filter", async () => {
    stubApi();
    goReports("#/reports?verdict=Verified");
    renderApp();

    await screen.findByText("newsletter.eml");
    expect(screen.queryByText("chase-alert.eml")).not.toBeInTheDocument();
  });

  it("opens full report details with agent code, copies the link and exports JSON", async () => {
    Object.defineProperty(window.navigator, "clipboard", {
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
      configurable: true,
    });
    (URL as unknown as Record<string, unknown>)["createObjectURL"] = vi.fn(() => "blob:mock");
    (URL as unknown as Record<string, unknown>)["revokeObjectURL"] = vi.fn();
    const anchors: HTMLAnchorElement[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      anchors.push(this);
    });

    stubApi();
    goReports();
    renderApp();

    await screen.findByText("chase-alert.eml");
    openRow("chase-alert.eml");
    expect(await screen.findByText("Lookalike domain chase-secure.co imitates chase.com")).toBeInTheDocument();
    expect(
      await screen.findByText("This email is a phishing attempt impersonating Chase."),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Show code" }));
    expect(screen.getByText("# scan.py — written by the agent")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy report link" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Copied" })).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: /Export JSON/ }));
    expect(anchors.length).toBeGreaterThan(0);
    expect(anchors[0]?.getAttribute("download")).toBe("phishshield-report-r1.json");
  });

  it("shows deep scan run comparisons", async () => {
    const deep: ScanSummary = {
      id: "d1",
      t: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
      filename: "deep.eml",
      verdict: "Malicious",
      score: 69,
      reasons: ["Deep findings"],
      iocs: { sha256: "ddd", domains: [], urls: [] },
      kind: "email",
      deep: true,
      mode: "mock-sandbox (deep)",
      runs: [
        { profile: "standard", verdict: "Suspicious", score: 55 },
        { profile: "strict", verdict: "Malicious", score: 69 },
      ],
      agreement: false,
    };
    stubApi({ history: [deep] });
    goReports();
    renderApp();

    await screen.findByText("deep.eml");
    openRow("deep.eml");
    expect(await screen.findByText("standard variant")).toBeInTheDocument();
    expect(within(screen.getByRole("dialog")).getByText("Deep scan")).toBeInTheDocument();
    expect(screen.getByText("strict variant")).toBeInTheDocument();
    expect(screen.getByText(/Variants disagree/)).toBeInTheDocument();
  });

  it("deletes a report with confirmation", async () => {
    const fetchMock = stubApi();
    goReports();
    renderApp();

    await screen.findByText("chase-alert.eml");
    openRow("chase-alert.eml");
    await screen.findByText("Lookalike domain chase-secure.co imitates chase.com");
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    fireEvent.click(await screen.findByRole("button", { name: "Confirm delete" }));

    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          ([input, init]) =>
            typeof input === "string" &&
            input.includes("/api/analyze/report/r1") &&
            init?.method === "DELETE",
        ),
      ).toBe(true),
    );
    await waitFor(() => expect(screen.queryByText("chase-alert.eml")).not.toBeInTheDocument());
  });

  it("offers a first-scan action when the archive is empty", async () => {
    stubApi({ history: [] });
    goReports();
    renderApp();

    const cta = await screen.findByRole("button", { name: "Start your first scan" });
    fireEvent.click(cta);
    expect(window.location.hash).toBe("#/");
  });
});
