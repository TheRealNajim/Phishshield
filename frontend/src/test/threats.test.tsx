import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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

function goThreats(hash = "#/threats") {
  window.location.hash = hash;
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.location.hash = "";
  window.history.pushState({}, "", "/");
});

describe("threats queue", () => {
  it("shows summary counts, rows with category, score and report links", async () => {
    stubApi();
    goThreats();
    renderApp();

    expect(await screen.findByText("chase-alert.eml")).toBeInTheDocument();
    expect(screen.getByText("newsletter.eml")).toBeInTheDocument();
    expect(screen.getByText("Brand impersonation")).toBeInTheDocument();
    expect(screen.getByText("Risk score 200")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("filters the queue by verdict tab", async () => {
    stubApi();
    goThreats();
    renderApp();

    await screen.findByText("chase-alert.eml");
    fireEvent.click(screen.getByRole("button", { name: "Suspicious" }));
    expect(screen.queryByText("chase-alert.eml")).not.toBeInTheDocument();
    expect(screen.getByText("No threats match these filters.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Malicious" }));
    expect(screen.getByText("chase-alert.eml")).toBeInTheDocument();
    expect(screen.queryByText("newsletter.eml")).not.toBeInTheDocument();
  });

  it("honours a deep-linked verdict filter", async () => {
    stubApi();
    goThreats("#/threats?verdict=Malicious");
    renderApp();

    await screen.findByText("chase-alert.eml");
    expect(screen.queryByText("newsletter.eml")).not.toBeInTheDocument();
  });

  it("opens the investigation drawer and deletes with confirmation", async () => {
    const fetchMock = stubApi();
    goThreats();
    renderApp();

    fireEvent.click(await screen.findByRole("button", { name: /chase-alert\.eml/ }));
    expect(
      await screen.findByText("Lookalike domain chase-secure.co imitates chase.com"),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open full report" })).toHaveAttribute("href", "/v/r1");

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
});
