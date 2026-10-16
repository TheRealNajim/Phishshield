import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "@/App";
import { historyFixture, stubApi } from "./mock-api";

// Failed lookups surface immediately in tests instead of after react-query's retry backoff.
function renderApp() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>,
  );
}

function postsTo(fetchMock: ReturnType<typeof stubApi>, fragment: string) {
  return fetchMock.mock.calls.some(([input, init]) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    return url.includes(fragment) && (init?.method ?? "GET").toUpperCase() === "POST";
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.history.pushState({}, "", "/");
});

describe("dashboard data wiring", () => {
  it("shows stats, rows and severity shares derived from the real history payload", async () => {
    stubApi();
    renderApp();

    // Two stored reports: one malicious, one verified -> 50/0/50 split.
    expect(await screen.findByText("Critical 50%")).toBeInTheDocument();
    expect(screen.getByText("High 0%")).toBeInTheDocument();
    expect(screen.getByText("Low 50%")).toBeInTheDocument();
    expect(screen.getByText("Critical Threats")).toBeInTheDocument();

    expect(screen.getByText("chase-alert.eml")).toBeInTheDocument();
    expect(screen.getByText("newsletter.eml")).toBeInTheDocument();
    expect(screen.getAllByText("mock-sandbox (local)").length).toBe(2);
  });

  it("explains an empty report store instead of showing fake rows", async () => {
    stubApi({ history: [] });
    renderApp();

    expect(await screen.findByText(/No scans yet/)).toBeInTheDocument();
    expect(screen.getByText("Critical 0%")).toBeInTheDocument();
  });

  it("surfaces a history failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          ({
            ok: false,
            status: 500,
            json: async () => ({ error: "history down" }),
            text: async () => "",
          }) as unknown as Response,
      ),
    );
    renderApp();

    expect(
      await screen.findByText(/Could not load verdict history: history down/),
    ).toBeInTheDocument();
  });
  it("opens scan details in a modal instead of a new tab", async () => {
    stubApi();
    renderApp();

    const viewButtons = await screen.findAllByRole("button", { name: "View" });
    const firstView = viewButtons[0];
    if (!firstView) throw new Error("no View buttons rendered");
    fireEvent.click(firstView);

    const modal = await screen.findByRole("dialog", { name: /Scan details/ });
    expect(
      await within(modal).findByText("Lookalike domain chase-secure.co imitates chase.com"),
    ).toBeInTheDocument();
    expect(
      await within(modal).findByText("This email is a phishing attempt impersonating Chase."),
    ).toBeInTheDocument();
  });
});

describe("scan panel", () => {
  it("submits a pasted email and renders the verdict, reasons and agent code", async () => {
    const fetchMock = stubApi();
    renderApp();

    fireEvent.click(await screen.findByRole("button", { name: "Bank email" }));
    fireEvent.change(screen.getByPlaceholderText(/Paste the raw message/), {
      target: { value: 'From: "Chase Bank" <alerts@chase-secure.co>' },
    });
    fireEvent.click(screen.getByRole("button", { name: /Get verdict/ }));

    expect(
      await screen.findByText(/Lookalike domain chase-secure\.co imitates chase\.com/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Asks for BVN\/NIN\/OTP\/PIN/)).toBeInTheDocument();
    expect(
      screen.getByText("This email is a phishing attempt impersonating Chase."),
    ).toBeInTheDocument();
    expect(screen.getByText(/Do not reply or click anything/)).toBeInTheDocument();
    expect(screen.getByText(/scan\.py — written and run by the agent/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Share report" })).toHaveAttribute("href", "/v/new1");
    expect(postsTo(fetchMock, "/api/analyze")).toBe(true);
  });

  it("streams the agent's script while it works, then swaps in the report", async () => {
    // Hold the verdict frame open so the in-flight view can be inspected.
    let release: () => void = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const fetchMock = stubApi({ stream: true, streamHold: () => held });
    renderApp();

    fireEvent.click(await screen.findByRole("button", { name: "Bank email" }));
    fireEvent.change(screen.getByPlaceholderText(/Paste the raw message/), {
      target: { value: "From: a@chase-secure.co" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Get verdict/ }));

    // The agent view opens, its script streams in, and it reports each model it asks.
    const agent = await screen.findByRole("dialog", { name: /analysing/i });
    expect(await within(agent).findByText(/written by PhishShield agent/)).toBeInTheDocument();
    expect(await within(agent).findByText("Running the analyser")).toBeInTheDocument();
    // The model is listed twice as it is tried, then answers — so match any.
    expect(
      (await within(agent).findAllByText(/groq\/llama-3\.3-70b-versatile/)).length,
    ).toBeGreaterThan(0);

    // Releasing the verdict replaces the modal with the report in the panel.
    release();
    expect(
      await screen.findByText(/Lookalike domain chase-secure\.co imitates chase\.com/),
    ).toBeInTheDocument();
    expect(screen.queryByRole("dialog", { name: /analysing/i })).not.toBeInTheDocument();
    expect(postsTo(fetchMock, "/api/analyze/stream")).toBe(true);
  });

  it("sends deep scans to /api/analyze/deep and compares both variants", async () => {
    const fetchMock = stubApi();
    renderApp();

    fireEvent.click(await screen.findByRole("button", { name: /Deep scan ·/ }));
    fireEvent.click(screen.getByRole("button", { name: "Bank email" }));
    fireEvent.change(screen.getByPlaceholderText(/Paste the raw message/), {
      target: { value: "From: someone@example.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Deep scan" }));

    expect(await screen.findByText("standard variant")).toBeInTheDocument();
    expect(screen.getByText("strict variant")).toBeInTheDocument();
    expect(screen.getByText(/Variants disagree/)).toBeInTheDocument();
    expect(postsTo(fetchMock, "/api/analyze/deep")).toBe(true);
  });

  it("reports a rate-limit error from the API", async () => {
    stubApi({
      scanStatus: 429,
      scanError: "Free tier: 30 scans/hour. Upgrade to Teams for unlimited.",
    });
    renderApp();

    fireEvent.click(await screen.findByRole("button", { name: "Bank email" }));
    fireEvent.change(screen.getByPlaceholderText(/Paste the raw message/), {
      target: { value: "hello" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Get verdict/ }));

    expect(await screen.findByText(/Free tier: 30 scans\/hour/)).toBeInTheDocument();
  });
});
