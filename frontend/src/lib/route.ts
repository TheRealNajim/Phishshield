import { useEffect, useState } from "react";

export interface Route {
  /** App path: "/", "/analytics", … or "__unknown" for unmatched server paths. */
  path: string;
  /** Query parameters parsed from the hash (e.g. "#/threats?verdict=Malicious"). */
  params: URLSearchParams;
}

function parseHash(): Route {
  if (typeof window === "undefined") return { path: "/", params: new URLSearchParams() };
  const raw = window.location.hash.replace(/^#/, "");
  if (!raw || raw === "/") return { path: "/", params: new URLSearchParams() };
  const [pathname, search] = raw.split("?");
  return { path: pathname || "/", params: new URLSearchParams(search ?? "") };
}

/** Current workspace route. Anything off "/" keeps the previous not-found behaviour. */
export function useRoute(): Route {
  const [route, setRoute] = useState(parseHash);
  useEffect(() => {
    const onChange = () => setRoute(parseHash());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);

  const pathname = typeof window === "undefined" ? "/" : window.location.pathname;
  if (pathname !== "/" && pathname !== "/index.html") {
    return { path: "__unknown", params: new URLSearchParams() };
  }
  return route;
}

export function navigate(to: string) {
  window.location.hash = to;
}
