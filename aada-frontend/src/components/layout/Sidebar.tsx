import { NavLink } from "react-router-dom";
import { LayoutDashboard, AlertTriangle, Search, FileText, Settings, Shield } from "lucide-react";
import { cn } from "@/lib/utils";
import { useAppStore } from "@/store/appStore";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/alerts", label: "Alerts", icon: AlertTriangle },
  { to: "/investigations", label: "Investigations", icon: Search },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const collapsed = useAppStore((s) => s.sidebarCollapsed);
  return (
    <aside
      className={cn(
        "flex h-screen flex-col border-r border-border bg-card transition-all",
        collapsed ? "w-16" : "w-60",
      )}
    >
      <div className="flex h-16 items-center gap-2 px-4">
        <Shield className="size-7 shrink-0 text-primary" />
        {!collapsed && (
          <div className="leading-tight">
            <p className="text-sm font-bold tracking-tight">AADA</p>
            <p className="text-[10px] text-muted-foreground">Autonomous Defense</p>
          </div>
        )}
      </div>
      <nav className="flex-1 space-y-1 px-2 py-3">
        {NAV.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-primary/15 text-primary"
                  : "text-muted-foreground hover:bg-accent hover:text-foreground",
              )
            }
          >
            <Icon className="size-5 shrink-0" />
            {!collapsed && label}
          </NavLink>
        ))}
      </nav>
      {!collapsed && (
        <div className="border-t border-border p-3 text-[10px] text-muted-foreground">
          v0.1 · {new Date().getFullYear()}
        </div>
      )}
    </aside>
  );
}
