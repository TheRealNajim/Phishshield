import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AppErrorBoundary, NotFoundPage } from "@/components/app-boundary";

function Boom(): never {
  throw new Error("kaboom");
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AppErrorBoundary", () => {
  it("renders the failure card and logs the error when a child throws", () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

    render(
      <AppErrorBoundary>
        <Boom />
      </AppErrorBoundary>,
    );

    expect(screen.getByText("This page didn't load")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go home" })).toHaveAttribute("href", "/");
    expect(consoleError).toHaveBeenCalledWith(expect.any(Error), expect.anything());
  });

  it("renders children when nothing throws", () => {
    render(
      <AppErrorBoundary>
        <p>all clear</p>
      </AppErrorBoundary>,
    );

    expect(screen.getByText("all clear")).toBeInTheDocument();
    expect(screen.queryByText("This page didn't load")).not.toBeInTheDocument();
  });
});

describe("NotFoundPage", () => {
  it("links back to the dashboard", () => {
    render(<NotFoundPage />);

    expect(screen.getByText("404")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go home" })).toHaveAttribute("href", "/");
  });
});
