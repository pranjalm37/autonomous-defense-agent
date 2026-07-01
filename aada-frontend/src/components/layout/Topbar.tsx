import { Menu, ShieldCheck, Eye, Bot, LogOut } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { useAppStore } from "@/store/appStore";
import { useMe, useLogout } from "@/hooks/useAuth";
import type { DecisionMode } from "@/lib/types";

const MODES: { value: DecisionMode; label: string; icon: typeof Eye; hint: string }[] = [
  { value: "monitor", label: "Monitor", icon: Eye, hint: "Observe only" },
  { value: "assisted", label: "Assisted", icon: ShieldCheck, hint: "Human approves" },
  { value: "autonomous", label: "Autonomous", icon: Bot, hint: "Auto-act (safe)" },
];

const ROLE_VARIANT: Record<string, "default" | "destructive" | "muted"> = {
  admin: "destructive", analyst: "default", viewer: "muted",
};

export function Topbar() {
  const toggleSidebar = useAppStore((s) => s.toggleSidebar);
  const mode = useAppStore((s) => s.defenseMode);
  const setMode = useAppStore((s) => s.setDefenseMode);
  const { data: me } = useMe();
  const logout = useLogout();

  return (
    <header className="flex h-16 items-center justify-between border-b border-border bg-card/40 px-4 backdrop-blur">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="icon" onClick={toggleSidebar} aria-label="Toggle sidebar">
          <Menu className="size-5" />
        </Button>
        <h1 className="text-sm font-semibold text-muted-foreground">Security Operations Center</h1>
      </div>

      <div className="flex items-center gap-4">
        {/* Defense-mode switcher — the single most consequential control */}
        <div className="flex items-center gap-2">
          <span className="hidden text-xs text-muted-foreground sm:inline">Defense mode</span>
          <div className="flex rounded-lg border border-border bg-background/50 p-0.5">
            {MODES.map(({ value, label, icon: Icon, hint }) => (
              <button
                key={value}
                title={hint}
                onClick={() => setMode(value)}
                className={cn(
                  "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
                  mode === value
                    ? value === "autonomous"
                      ? "bg-sev-high/20 text-sev-high"
                      : "bg-primary/20 text-primary"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                <Icon className="size-3.5" />
                {label}
              </button>
            ))}
          </div>
        </div>

        {/* Current user + role + logout */}
        <div className="flex items-center gap-2 border-l border-border pl-3">
          <div className="hidden text-right leading-tight sm:block">
            <p className="text-xs font-medium">{me?.full_name ?? me?.email ?? "—"}</p>
            {me?.role && <Badge variant={ROLE_VARIANT[me.role] ?? "muted"} className="mt-0.5 capitalize">{me.role}</Badge>}
          </div>
          <Button variant="ghost" size="icon" onClick={logout} aria-label="Sign out" title="Sign out">
            <LogOut className="size-4" />
          </Button>
        </div>
      </div>
    </header>
  );
}
