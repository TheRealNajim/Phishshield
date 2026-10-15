import { AppErrorBoundary, NotFoundPage } from "./components/app-boundary";
import { Dashboard } from "./pages/Dashboard";

// The app has a single route ("/"). Anything else keeps the previous
// not-found behaviour now that no router is mounted.
function isHome(pathname: string) {
  return pathname === "/" || pathname === "/index.html";
}

export function App() {
  const pathname = typeof window === "undefined" ? "/" : window.location.pathname;

  return <AppErrorBoundary>{isHome(pathname) ? <Dashboard /> : <NotFoundPage />}</AppErrorBoundary>;
}
