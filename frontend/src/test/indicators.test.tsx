import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "@/App";
import { stubApi } from "./mock-api";

function renderApp() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>,
  );
}

function goIndicators(hash = "#/indicators") {
  window.location.hash = hash;
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.location.hash = "";
  window.history.pushState({}, "", "/");
});

describe("indicators inventory", () => {
  it("lists artifacts by type with per-artifact assessment", async () => {
    stubApi();
    goIndicators();
    renderApp();

    expect(await screen.findByText("chase-secure.co")).toBeInTheDocument();
    expect(screen.getByText("http://192.168.1.99/login")).toBeInTheDocument();
    expect(screen.getByText("192.168.1.99")).toBeInTheDocument();
    expect(screen.getByText("deadbeef")).toBeInTheDocument();
    // Only the indicator named in malicious evidence is assessed malicious.
    expect(screen.getByText("High-risk indicators")).toBeInTheDocument();
  });

  it("filters by type tab, assessment and search", async () => {
    stubApi();
    goIndicators();
    renderApp();

    await screen.findByText("chase-secure.co");
    fireEvent.click(screen.getByRole("button", { name: "URLs" }));
    expect(screen.getByText("http://192.168.1.99/login")).toBeInTheDocument();
    expect(screen.queryByText("deadbeef")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "All types" }));

    fireEvent.click(screen.getByRole("button", { name: "Assessment" }));
    fireEvent.click(await screen.findByRole("menuitem", { name: "Malicious" }));
    expect(screen.getByText("chase-secure.co")).toBeInTheDocument();
    expect(screen.queryByText("github.com")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Assessment" }));
    fireEvent.click(await screen.findByRole("menuitem", { name: "All assessments" }));
    fireEvent.change(screen.getByPlaceholderText("Search indicators"), {
      target: { value: "github" },
    });
    expect(screen.getByText("github.com")).toBeInTheDocument();
    expect(screen.queryByText("chase-secure.co")).not.toBeInTheDocument();
  });

  it("opens details with evidence, brand, related reports and source link", async () => {
    Object.defineProperty(window.navigator, "clipboard", {
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
      configurable: true,
    });
    stubApi();
    goIndicators();
    renderApp();

    await screen.findByText("chase-secure.co");
    const row = screen.getByText("chase-secure.co").closest("div");
    if (!row) throw new Error("indicator row missing");
    fireEvent.click(within(row as HTMLElement).getByRole("button", { name: "View details" }));

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Lookalike domain chase-secure.co imitates chase.com")).toBeInTheDocument();
    expect(within(dialog).getByText("chase.com")).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "View" }));
    const scanModal = await screen.findByRole("dialog", { name: /Scan details/ });
    expect(
      await within(scanModal).findByText("Lookalike domain chase-secure.co imitates chase.com"),
    ).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: "View in Sources" })).toHaveAttribute(
      "href",
      "#/sources?q=chase-secure.co",
    );

    fireEvent.click(within(dialog).getByRole("button", { name: "Copy indicator" }));
    await waitFor(() => expect(within(dialog).getByRole("button", { name: "Copied" })).toBeInTheDocument());

    delete (window.navigator as unknown as Record<string, unknown>)["clipboard"];
  });
});
