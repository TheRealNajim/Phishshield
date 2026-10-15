import type { ReactNode } from "react";

import { AppErrorBoundary, NotFoundPage } from "./components/app-boundary";
import { useRoute } from "./lib/route";
import { Analytics } from "./pages/Analytics";
import { Dashboard } from "./pages/Dashboard";
import { Indicators } from "./pages/Indicators";
import { Reports } from "./pages/Reports";
import { Sources } from "./pages/Sources";
import { Threats } from "./pages/Threats";

export function App() {
  const { path } = useRoute();

  let page: ReactNode;
  if (path === "/") {
    page = <Dashboard />;
  } else if (path === "/analytics") {
    page = <Analytics />;
  } else if (path === "/threats") {
    page = <Threats />;
  } else if (path === "/sources") {
    page = <Sources />;
  } else if (path === "/reports") {
    page = <Reports />;
  } else if (path === "/indicators") {
    page = <Indicators />;
  } else {
    page = <NotFoundPage />;
  }

  return <AppErrorBoundary>{page}</AppErrorBoundary>;
}
