import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "@/App";
import { stubApi } from "./mock-api";

function renderApp() {
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <App />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.history.pushState({}, "", "/");
});

describe("App", () => {
  it("renders the dashboard for /", async () => {
    stubApi();
    renderApp();

    expect(screen.getByAltText("DeceptIQ")).toBeInTheDocument();
    expect(screen.getByText("Threat Trend by Severity")).toBeInTheDocument();
    expect(screen.getByText("Severity Distribution")).toBeInTheDocument();
    expect(await screen.findByText("chase-alert.eml")).toBeInTheDocument();
  });

  it("renders the not-found page for unknown paths", () => {
    stubApi();
    window.history.pushState({}, "", "/nope");
    renderApp();

    expect(screen.getByText("Page not found")).toBeInTheDocument();
  });
});
