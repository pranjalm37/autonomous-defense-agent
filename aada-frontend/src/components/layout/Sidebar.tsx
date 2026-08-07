import { NavLink } from "react-router-dom";
import { Activity, FileText, ScrollText, Search, Settings, Shield } from "lucide-react";
import { cn } from "@/lib/utils";
import { useAlerts, useActions } from "@/hooks/queries";

const NAV = [
  { to: "/", label: "Triage", icon: Activity, end: true },
  { to: "/alerts", label: "Alerts", icon: ScrollText },
  { to: "/investigations", label: "Investigate", icon: Search },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const { data: alerts } = useAlerts({ limit: 100 });
  const { data: pending } = useActions("pending");

  const open = (alerts?.items ?? []).filter(
    (a) => !["resolved", "false_positive"].includes(a.status),
  ).length;

  return (
    <aside className="flex h-screen w-[190px] flex-col border-r border-rule bg-pane">
      <div className="flex items-baseline gap-2 border-b border-rule px-4 py-3.5">
        <Shield className="size-4 self-center text-ink" strokeWidth={1.6} />
        <span className="text-lg font-bold tracking-tight">AADA</span>
        <span className="data text-2xs tracking-widest text-ink-3">v0.2</span>
      </div>

      <nav className="flex flex-col py-1.5">
        {NAV.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              cn(
                // The active marker is a hairline against the pane edge, not a filled pill.
                "relative flex items-center gap-2.5 px-4 py-1.5 text-sm transition-colors",
                "before:absolute before:left-0 before:top-1 before:bottom-1 before:w-[2px]",
                isActive
                  ? "font-semibold text-ink before:bg-ink"
                  : "text-ink-2 before:bg-transparent hover:text-ink",
              )
            }
          >
            <Icon className="size-3.5 shrink-0" strokeWidth={1.6} />
            <span className="flex-1">{label}</span>
            {to === "/" && open > 0 && <span className="data text-xs text-sev-critical">{open}</span>}
            {to === "/alerts" && (pending?.length ?? 0) > 0 && (
              <span className="data text-xs text-sev-high">{pending?.length}</span>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="mt-auto flex flex-col gap-1.5 border-t border-rule px-4 py-3">
        <Row label="Pipeline" value="HEALTHY" tone="ok" />
        <Row label="Open alerts" value={String(open)} />
        <Row label="Queue" value={String(pending?.length ?? 0)} />
      </div>
    </aside>
  );
}

function Row({ label, value, tone }: { label: string; value: string; tone?: "ok" }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span className="text-ink-3">{label}</span>
      <span className={cn("data", tone === "ok" ? "text-ok" : "text-ink")}>{value}</span>
    </div>
  );
}
