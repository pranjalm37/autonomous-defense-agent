import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAlerts } from "@/hooks/queries";
import { cn, timeAgo } from "@/lib/utils";
import type { Severity } from "@/lib/types";

const SEVERITIES: (Severity | "all")[] = ["all", "critical", "high", "medium", "low", "info"];

const SEV_TEXT: Record<Severity, string> = {
  critical: "text-sev-critical", high: "text-sev-high", medium: "text-sev-medium",
  low: "text-sev-low", info: "text-sev-info",
};
const SEV_BG: Record<Severity, string> = {
  critical: "bg-sev-critical", high: "bg-sev-high", medium: "bg-sev-medium",
  low: "bg-sev-low", info: "bg-sev-info",
};
const SEV_ABBR: Record<Severity, string> = {
  critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW", info: "INFO",
};
const STATUS_TEXT: Record<string, string> = {
  new: "text-sev-low", analyzing: "text-ink-2", confirmed: "text-sev-high",
  escalated: "text-sev-critical", resolved: "text-ok", false_positive: "text-ink-3",
};

export default function Alerts() {
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [q, setQ] = useState("");
  const navigate = useNavigate();
  const { data, isLoading } = useAlerts({
    severity: severity === "all" ? undefined : severity,
    limit: 200,
  });

  const items = (data?.items ?? []).filter(
    (a) => !q || a.title.toLowerCase().includes(q.toLowerCase()) || (a.source_ip ?? "").includes(q),
  );

  return (
    <div className="flex h-full flex-col">
      <div className="flex h-11 shrink-0 items-center gap-2.5 border-b border-rule bg-pane px-3.5">
        <span className="eyebrow">Alerts</span>
        <span className="data text-xs text-ink-3">{items.length} of {data?.total ?? 0}</span>

        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search title or IP…"
          aria-label="Search alerts"
          className="data ml-3 w-56 border border-rule-2 bg-void px-2 py-1 text-xs text-ink placeholder:text-ink-3 focus:border-ink focus:outline-none"
        />

        <div className="ml-auto flex gap-1">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              onClick={() => setSeverity(s)}
              className={cn(
                "data border px-2 py-0.5 text-2xs tracking-wide",
                severity === s ? "border-rule-2 text-ink" : "border-transparent text-ink-3 hover:text-ink",
              )}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto bg-pane">
        <table className="w-full min-w-[860px] table-fixed border-collapse">
          <colgroup>
            <col className="w-[74px]" /><col /><col className="w-[132px]" />
            <col className="w-[124px]" /><col className="w-[92px]" />
            <col className="w-[104px]" /><col className="w-[70px]" />
          </colgroup>
          <thead>
            <tr>
              {["Severity", "Title", "Source IP", "Threat", "Confidence", "Status", "Seen"].map((h, i) => (
                <th
                  key={h}
                  className={cn(
                    "eyebrow whitespace-nowrap border-b border-rule px-3 py-2 text-left font-medium",
                    (i === 4 || i === 6) && "text-right",
                  )}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr><td colSpan={7} className="px-3 py-6 text-sm text-ink-3">Loading alerts…</td></tr>
            )}
            {!isLoading && items.length === 0 && (
              <tr><td colSpan={7} className="px-3 py-6 text-sm text-ink-3">No alerts match.</td></tr>
            )}
            {items.map((a) => (
              <tr
                key={a.id}
                onClick={() => navigate(`/investigations?alert=${a.id}`)}
                className="cursor-pointer border-b border-rule hover:bg-pane-2"
              >
                <td className="relative py-2 pl-4 pr-3">
                  <span className={cn("absolute inset-y-0 left-0 w-[3px]", SEV_BG[a.severity])} aria-hidden />
                  <span className={cn("data text-2xs font-bold tracking-wider", SEV_TEXT[a.severity])}>
                    {SEV_ABBR[a.severity]}
                  </span>
                </td>
                <td className="truncate px-3 py-2 text-sm font-medium">{a.title}</td>
                <td className="data truncate px-3 py-2 text-xs text-ink-2">{a.source_ip ?? "—"}</td>
                <td className="data truncate px-3 py-2 text-xs text-ink-2">{a.threat_type ?? "—"}</td>
                <td className="data px-3 py-2 text-right text-sm font-semibold">
                  {a.ai_confidence != null ? `${Math.round(a.ai_confidence * 100)}%` : "—"}
                </td>
                <td className={cn("px-3 py-2 text-xs font-medium capitalize", STATUS_TEXT[a.status] ?? "text-ink-2")}>
                  {a.status.replace("_", " ")}
                </td>
                <td className="data px-3 py-2 text-right text-2xs text-ink-3">{timeAgo(a.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
