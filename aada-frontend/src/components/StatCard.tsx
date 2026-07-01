import type { LucideIcon } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export function StatCard({
  label, value, icon: Icon, tone = "default", hint,
}: {
  label: string;
  value: string | number;
  icon: LucideIcon;
  tone?: "default" | "critical" | "ok" | "warning";
  hint?: string;
}) {
  const toneColor = {
    default: "text-primary",
    critical: "text-sev-critical",
    ok: "text-ok",
    warning: "text-sev-high",
  }[tone];

  return (
    <Card>
      <CardContent className="flex items-center justify-between p-5">
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
          <p className="mt-1 text-3xl font-bold tabular-nums">{value}</p>
          {hint && <p className="mt-0.5 text-xs text-muted-foreground">{hint}</p>}
        </div>
        <div className={cn("rounded-lg bg-background/40 p-3", toneColor)}>
          <Icon className="size-6" />
        </div>
      </CardContent>
    </Card>
  );
}
