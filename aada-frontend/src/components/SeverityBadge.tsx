import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";

const STYLES: Record<Severity, string> = {
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
  high: "bg-sev-high/15 text-sev-high border-sev-high/30",
  medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
  low: "bg-sev-low/15 text-sev-low border-sev-low/30",
  info: "bg-sev-info/15 text-sev-info border-sev-info/30",
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide",
        STYLES[severity] ?? STYLES.info,
        className,
      )}
    >
      {severity}
    </span>
  );
}

const STATUS_STYLES: Record<string, string> = {
  pending: "text-sev-medium", approved: "text-primary", denied: "text-muted-foreground",
  executing: "text-sev-low", completed: "text-ok", failed: "text-sev-critical",
  rolled_back: "text-muted-foreground", new: "text-sev-low", confirmed: "text-sev-high",
  false_positive: "text-muted-foreground", resolved: "text-ok", escalated: "text-sev-high",
};

export function StatusText({ status }: { status: string }) {
  return <span className={cn("text-xs font-medium capitalize", STATUS_STYLES[status] ?? "text-foreground")}>{status.replace("_", " ")}</span>;
}
