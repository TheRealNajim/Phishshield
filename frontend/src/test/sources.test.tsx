import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "@/App";
import type { ScanSummary } from "@/lib/api";
import { historyFixture, stubApi } from "./mock-api";

function renderApp() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>,
  );
}

function goSources(hash = "#/sources") {
  window.location.hash = hash;
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.location.hash = "";
  window.history.pushState({}, "", "/");
});

describe("sources directory", () => {
  it("aggregates sources with honest verdicts and counts", async () => {
    stubApi();
    goSources();
    renderApp();

    expect(await screen.findByText("chase-secure.co")).toBeInTheDocument();
    expect(screen.getByText("192.168.1.99")).toBeInTheDocument();
    expect(screen.getByText("github.com")).toBeInTheDocument();
    expect(screen.getByText("Lookalike domain")).toBeInTheDocument();
    expect(screen.getByText("Link destination")).toBeInTheDocument();
    expect(screen.getByText("Observed domain")).toBeInTheDocument();
  });

  it("filters by verdict and search", async () => {
    stubApi();
    goSources();
    renderApp();

    await screen.findByText("chase-secure.co");
    fireEvent.click(screen.getByRole("button", { name: "Source verdict" }));
    fireEvent.click(await screen.findByRole("menuitem", { name: "Verified" }));
    expect(screen.queryByText("chase-secure.co")).not.toBeInTheDocument();
    expect(screen.getByText("github.com")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Source verdict" }));
    fireEvent.click(await screen.findByRole("menuitem", { name: "All verdicts" }));
    fireEvent.change(screen.getByPlaceholderText("Search domains or brands"), {
      target: { value: "chase.com" },
    });
    expect(screen.getByText("chase-secure.co")).toBeInTheDocument();
    expect(screen.queryByText("github.com")).not.toBeInTheDocument();
  });

  it("counts repeat sources across scans", async () => {
    const dupe: ScanSummary = {
      id: "r3",
      t: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
      filename: "chase-again.eml",
      verdict: "Suspicious",
      score: 40,
      reasons: ["Suspicious link"],
      iocs: { sha256: "fff", domains: ["chase-secure.co"], urls: [] },
      kind: "email",
      size: 512,
      mode: "mock-sandbox (local)",
    };
    stubApi({ history: [...historyFixture(), dupe] });
    goSources();
    renderApp();

    await screen.findByText("chase-secure.co");
    expect(screen.getByRole("button", { name: "Repeat sources" })).toBeInTheDocument();
  });

  it("opens a source investigation with evidence and related reports", async () => {    stubApi();
    goSources();
    renderApp();

    fireEvent.click(await screen.findByRole("button", { name: /chase-secure\.co/ }));
    expect(await screen.findByText("Lookalike domain chase-secure.co imitates chase.com")).toBeInTheDocument();
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("chase.com")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View" })).toHaveAttribute("href", "/v/r1");
    expect(screen.getByRole("link", { name: "Open in Indicators" })).toHaveAttribute(
      "href",
      "#/indicators",
    );
  });

  it("prefills search from a deep link", async () => {
    stubApi();
    goSources("#/sources?q=github");
    renderApp();

    await screen.findByText("github.com");
    expect(screen.getByPlaceholderText("Search domains or brands")).toHaveValue("github");
    expect(screen.queryByText("chase-secure.co")).not.toBeInTheDocument();
  });
});
