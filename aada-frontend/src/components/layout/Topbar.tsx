import { useLocation } from "react-router-dom";
import { Bot, Eye, LogOut, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";
import { useAppStore } from "@/store/appStore";
import { useMe, useLogout } from "@/hooks/useAuth";
import type { DecisionMode } from "@/lib/types";

const MODES: { value: DecisionMode; label: string; icon: typeof Eye; hint: string }[] = [
  { value: "monitor", label: "Monitor", icon: Eye, hint: "Observe only — nothing is queued" },
  { value: "assisted", label: "Assisted", icon: ShieldCheck, hint: "Actions require human approval" },
  { value: "autonomous", label: "Autonomous", icon: Bot, hint: "Reversible, low-risk actions run automatically" },
];

const CRUMBS: Record<string, string> = {
  "/": "triage",
  "/simulator": "simulator",
  "/alerts": "alerts",
  "/investigations": "investigate",
  "/reports": "reports",
  "/settings": "settings",
};

export function Topbar() {
  const mode = useAppStore((s) => s.defenseMode);
  const setMode = useAppStore((s) => s.setDefenseMode);
  const { data: me } = useMe();
  const logout = useLogout();
  const { pathname } = useLocation();

  return (
    <header className="flex h-11 shrink-0 items-center gap-4 border-b border-rule bg-pane px-3.5">
      <div className="data text-xs text-ink-3">
        soc <span className="text-rule-2">/</span>{" "}
        <span className="font-medium text-ink">{CRUMBS[pathname] ?? "console"}</span>
      </div>

      {/* Defense mode — the single most consequential control, so it reads as a switch. */}
      <div className="ml-auto flex border border-rule-2">
        {MODES.map(({ value, label, icon: Icon, hint }) => (
          <button
            key={value}
            title={hint}
            onClick={() => setMode(value)}
            className={cn(
              "data flex items-center gap-1.5 border-r border-rule-2 px-2.5 py-1 text-2xs uppercase tracking-wider last:border-r-0",
              "focus-visible:outline focus-visible:outline-1 focus-visible:outline-ink",
              mode === value ? "bg-ink font-bold text-void" : "text-ink-3 hover:text-ink",
            )}
          >
            <Icon className="size-3" strokeWidth={2} />
            {label}
          </button>
        ))}
      </div>

      <div className="flex items-center gap-2 border-l border-rule pl-3.5">
        <span className="size-1.5 rounded-full bg-ok" aria-hidden />
        <span className="data text-xs text-ink-2">{me?.email ?? "—"}</span>
        {me?.role && (
          <span className="data text-2xs uppercase tracking-wider text-sev-critical">{me.role}</span>
        )}
        <button
          onClick={logout}
          aria-label="Sign out"
          title="Sign out"
          className="ml-1 text-ink-3 transition-colors hover:text-ink focus-visible:outline focus-visible:outline-1 focus-visible:outline-ink"
        >
          <LogOut className="size-3.5" strokeWidth={1.6} />
        </button>
      </div>
    </header>
  );
}
