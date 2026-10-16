import { useEffect, useState, type ReactNode } from "react";
import {
  BarChart3, Bug, FileText, Gauge, LayoutGrid, Users,
  Home, ChevronRight, Search, Moon, Sun, Menu,
} from "lucide-react";

import { navigate, useRoute } from "@/lib/route";

type NavItem = { label: string; icon?: typeof LayoutGrid; heading?: boolean; to?: string };
const NAV: NavItem[] = [
  { label: "Dashboard", icon: LayoutGrid, to: "#/" },
  { label: "Analytics", icon: BarChart3, to: "#/analytics" },
  { label: "Threats Intelligence", heading: true },
  { label: "Threats", icon: Bug, to: "#/threats" },
  { label: "Sources", icon: Users, to: "#/sources" },
  { label: "Reports", icon: FileText, to: "#/reports" },
  { label: "Indicators", icon: Gauge, to: "#/indicators" },
];

export function WorkspaceShell({
  section,
  actions,
  children,
}: {
  section: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  const { path } = useRoute();

  const [collapsed, setCollapsed] = useState(false);
  const [dark, setDark] = useState(() => {
    if (typeof window === "undefined") return true;
    try {
      const stored = window.localStorage.getItem("sentinel-theme");
      return stored ? stored === "dark" : true;
    } catch {
      return true;
    }
  });

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    try {
      window.localStorage.setItem("sentinel-theme", dark ? "dark" : "light");
    } catch {
      /* storage unavailable */
    }
  }, [dark]);

  const isActive = (n: NavItem) => (n.to === "#/" ? path === "/" : !!n.to && path === n.to.slice(1));

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <aside className={`flex shrink-0 flex-col border-r border-border bg-chrome py-6 transition-all duration-300 ${collapsed ? "w-[68px] px-2" : "w-60 px-4"}`}>
        <div className={`flex items-center gap-2 px-2 text-on-chrome ${collapsed ? "justify-center px-0" : ""}`}>
          {collapsed ? (
            <img src="/favicon-2.png" alt="DeceptIQ mark" className="h-8 w-8 shrink-0 rounded-[3px]" />
          ) : (
            <img src="/logo.png" alt="DeceptIQ" className="h-8 w-auto" />
          )}
        </div>
        <p className={`mt-10 px-2 text-sm uppercase text-on-chrome-muted ${collapsed ? "invisible" : ""}`}>Overview</p>
        <nav className="mt-3 space-y-1 text-sm">
          {NAV.map((n) =>
            n.heading ? (
              <p key={n.label} className={`px-2 pb-1 pt-3 text-on-chrome-muted ${collapsed ? "invisible" : ""}`}>{n.label}</p>
            ) : (
              <button
                key={n.label}
                type="button"
                onClick={() => n.to && navigate(n.to)}
                aria-current={isActive(n) ? "page" : undefined}
                title={collapsed ? n.label : undefined}
                className={`flex w-full items-center gap-3 rounded-[3px] px-3 py-2.5 text-left ${collapsed ? "justify-center px-0" : ""} ${isActive(n) ? "nav-active-glow text-on-chrome" : "nav-link text-gray-400 hover:text-white"}`}
              >
                {n.icon && <n.icon size={18} />} {!collapsed && <span>{n.label}</span>}
              </button>
            ),
          )}
        </nav>
      </aside>

      <main className="content-gradient min-w-0 flex-1">
        <header className="flex items-center gap-4 border-b border-border bg-chrome px-6 py-4">
          <button
            type="button"
            onClick={() => setCollapsed((v) => !v)}
            aria-expanded={!collapsed}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className="cursor-pointer rounded-[3px] p-2 text-on-chrome"
          >
            <Menu size={16} />
          </button>
          <Home size={18} className="text-on-chrome-muted" />
          <ChevronRight size={14} className="text-on-chrome-muted" />
          <p className="text-sm text-on-chrome">{section}</p>
          <label className="ml-auto flex w-56 cursor-text items-center gap-2 rounded-[3px] border border-border px-3 py-2 text-sm text-on-chrome-muted"><Search size={16} /><input placeholder="Search" className="w-full bg-transparent text-on-chrome outline-none placeholder:text-on-chrome-muted" /></label>
          <button
            type="button"
            onClick={() => setDark((v) => !v)}
            aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}
            title={dark ? "Switch to light theme" : "Switch to dark theme"}
            className="cursor-pointer rounded-[3px] border border-border p-2 text-on-chrome"
          >
            {dark ? <Sun size={16} /> : <Moon size={16} />}
          </button>
          {actions}
        </header>

        {children}
      </main>
    </div>
  );
}
