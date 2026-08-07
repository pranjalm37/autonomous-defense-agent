import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Check, Play } from "lucide-react";
import { EventSpine } from "@/components/EventSpine";
import { useActions, useAlerts, useAnalyzeAlert, useDecideAlert, useEvents, useRunDetection } from "@/hooks/queries";
import { usePermissions } from "@/hooks/useAuth";
import { useAppStore } from "@/store/appStore";
import { cn, timeAgo } from "@/lib/utils";
import type { AIAnalysis, Action, Alert, Decision, Severity } from "@/lib/types";

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

export default function Triage() {
  const { data: alerts, isLoading } = useAlerts({ limit: 100 });
  const { data: events, isLoading: eventsLoading } = useEvents({ limit: 500 });
  const { data: pending } = useActions("pending");
  const runDetection = useRunDetection();
  const { can } = usePermissions();

  const [selected, setSelected] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | Severity>("all");

  const items = alerts?.items ?? [];
  const shown = filter === "all" ? items : items.filter((a) => a.severity === filter);

  // Keep a selection so the detail pane is never empty on load.
  useEffect(() => {
    if (!selected && shown.length > 0) setSelected(shown[0].id);
  }, [shown, selected]);

  const current = items.find((a) => a.id === selected) ?? null;
  const openCount = items.filter((a) => !["resolved", "false_positive"].includes(a.status)).length;

  return (
    <div className="flex h-full flex-col">
      <EventSpine events={events ?? []} loading={eventsLoading} />

      <div className="grid min-h-0 flex-1 grid-cols-1 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]">
        {/* ── stream ─────────────────────────────────────────── */}
        <section className="flex min-h-0 flex-col border-b border-rule bg-pane lg:border-b-0 lg:border-r">
          <div className="flex h-[34px] shrink-0 items-center gap-2.5 border-b border-rule px-3.5">
            <span className="eyebrow">Open alerts</span>
            <span className="data text-xs text-ink-3">{openCount}</span>
            <div className="ml-auto flex gap-1">
              {(["all", "critical", "high", "medium"] as const).map((f) => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={cn(
                    "data border px-1.5 py-0.5 text-2xs tracking-wide",
                    filter === f ? "border-rule-2 text-ink" : "border-transparent text-ink-3 hover:text-ink",
                  )}
                >
                  {f}
                </button>
              ))}
            </div>
            {can("detection", "run") && (
              <button
                onClick={() => runDetection.mutate(1440)}
                disabled={runDetection.isPending}
                className="data ml-1 flex items-center gap-1 border border-rule-2 px-2 py-0.5 text-2xs tracking-wide text-ink-2 hover:text-ink disabled:opacity-50"
              >
                <Play className="size-2.5" fill="currentColor" strokeWidth={0} />
                {runDetection.isPending ? "RUNNING" : "DETECT"}
              </button>
            )}
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto">
            {isLoading && <Muted>Loading alerts…</Muted>}
            {!isLoading && shown.length === 0 && <Muted>No alerts match this filter.</Muted>}
            {shown.map((a) => (
              <AlertRow
                key={a.id}
                alert={a}
                active={a.id === selected}
                onSelect={() => setSelected(a.id)}
              />
            ))}
          </div>
        </section>

        {/* ── investigation ──────────────────────────────────── */}
        <section className="min-h-0 overflow-y-auto bg-void">
          {current ? (
            <Investigation alert={current} pending={pending ?? []} />
          ) : (
            <Muted>Select an alert to investigate.</Muted>
          )}
        </section>
      </div>
    </div>
  );
}

/* ───────────────────────── alert row ───────────────────────── */

function AlertRow({ alert, active, onSelect }: { alert: Alert; active: boolean; onSelect: () => void }) {
  const resolved = ["resolved", "false_positive"].includes(alert.status);
  return (
    <button
      onClick={onSelect}
      className={cn(
        "relative grid w-full grid-cols-[3px_minmax(0,1fr)_auto] border-b border-rule text-left",
        active ? "bg-pane-2 after:absolute after:inset-y-0 after:right-0 after:w-[2px] after:bg-ink" : "hover:bg-pane-2",
      )}
    >
      <span className={cn("block h-full", resolved ? "bg-ok/50" : SEV_BG[alert.severity])} aria-hidden />
      <span className="min-w-0 px-3 py-2.5">
        <span className="mb-0.5 flex items-center gap-2">
          <span className={cn("data text-2xs font-bold tracking-wider", resolved ? "text-ink-3" : SEV_TEXT[alert.severity])}>
            {resolved ? "RESOLVED" : SEV_ABBR[alert.severity]}
          </span>
          <span className={cn("truncate text-sm", resolved ? "text-ink-2" : "font-medium text-ink")}>
            {alert.title}
          </span>
        </span>
        <span className="data block truncate text-xs text-ink-3">
          {alert.source_ip ?? "—"}
          {alert.hostname ? ` → ${alert.hostname}` : ""} · {alert.threat_type ?? "unknown"}
        </span>
      </span>
      <span className="flex flex-col items-end justify-center gap-0.5 px-3 py-2.5">
        <span className="data text-sm font-bold">
          {alert.ai_confidence != null ? `${Math.round(alert.ai_confidence * 100)}%` : "—"}
        </span>
        <span className="data text-2xs text-ink-3">{timeAgo(alert.created_at)}</span>
      </span>
    </button>
  );
}

/* ─────────────────────── investigation ─────────────────────── */

function Investigation({ alert, pending }: { alert: Alert; pending: Action[] }) {
  const analyze = useAnalyzeAlert();
  const decide = useDecideAlert();
  const mode = useAppStore((s) => s.defenseMode);
  const { can } = usePermissions();

  const [analysis, setAnalysis] = useState<AIAnalysis | null>(null);
  const [decision, setDecision] = useState<Decision | null>(null);

  // Results belong to the selected alert only.
  useEffect(() => { setAnalysis(null); setDecision(null); }, [alert.id]);

  const alertActions = useMemo(
    () => pending.filter((a) => a.alert_id === alert.id),
    [pending, alert.id],
  );

  const risk = decision?.risk_score ?? analysis?.risk_score ?? null;
  const confidence = decision?.confidence_score ?? analysis?.confidence ?? alert.ai_confidence;
  const analyzed = analysis != null || alert.ai_confidence != null;

  return (
    <>
      <div className="border-b border-rule p-3.5">
        <div className="flex items-start gap-3">
          <div className="min-w-0 flex-1">
            <h2 className="text-lg font-semibold leading-tight tracking-tight">{alert.title}</h2>
            <div className="data mt-1.5 flex flex-wrap text-xs text-ink-3">
              <Meta>{alert.source_ip ?? "no source"}</Meta>
              {alert.hostname && <Meta>{alert.hostname}</Meta>}
              {alert.affected_user && <Meta>{alert.affected_user}</Meta>}
              <Meta last>{timeAgo(alert.created_at)}</Meta>
            </div>
          </div>
          {risk != null && (
            <div className="shrink-0 text-right">
              <div className={cn("data text-3xl font-bold tracking-tighter", SEV_TEXT[alert.severity])}>
                {Math.round(risk)}
              </div>
              <div className="eyebrow mt-0.5">Risk</div>
            </div>
          )}
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <span className={cn("data px-2 py-0.5 text-xs font-bold uppercase tracking-wider", SEV_TEXT[alert.severity], "bg-pane-2")}>
            {alert.severity}
          </span>
          <span className="data px-2 py-0.5 text-xs uppercase tracking-wider text-ink-2 bg-pane-2">
            {alert.status.replace("_", " ")}
          </span>
          {decision && (
            <span className={cn("data px-2 py-0.5 text-xs font-bold uppercase tracking-wider bg-pane-2", SEV_TEXT[alert.severity])}>
              {decision.verdict}
            </span>
          )}
        </div>
      </div>

      <dl className="grid grid-cols-2 border-b border-rule">
        <Cell label="Confidence" value={confidence != null ? confidence.toFixed(2) : "not analyzed"} />
        <Cell label="Threat" value={alert.threat_type ?? "unknown"} last />
      </dl>
      <dl className="grid grid-cols-2 border-b border-rule">
        <Cell label="Disposition" value={decision ? decision.top_disposition.replace("_", " ") : "—"} />
        <Cell label="Queued actions" value={String(alertActions.length)} last />
      </dl>

      {(analysis || decision) && (
        <div className="border-b border-rule p-3.5">
          <span className="eyebrow mb-2 block">Assessment</span>
          <p className="max-w-[62ch] text-sm leading-relaxed text-ink-2">
            {analysis?.executive_summary ?? decision?.rationale}
          </p>
          {analysis && analysis.mitre_techniques.length > 0 && (
            <div className="mt-2.5 flex flex-wrap gap-1.5">
              {analysis.mitre_techniques.map((t) => (
                <span key={t.technique_id} className="data border border-rule-2 px-1.5 py-0.5 text-2xs text-ink-2">
                  {t.technique_id} {t.name}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Pipeline stages are derived from real state, not a fixed script. */}
      <div className="border-b border-rule p-3.5">
        <span className="eyebrow mb-2.5 block">Response pipeline</span>
        <ol className="flex flex-col">
          <Stage done label="Detected" detail={`${alert.threat_type ?? "rule match"} · severity ${alert.severity}`} />
          <Stage done={analyzed} label="Analyzed" detail={analyzed ? "LLM + RAG grounded assessment" : "not run yet"} />
          <Stage done={decision != null} label="Decided" detail={decision ? `risk ${Math.round(decision.risk_score)} · ${decision.mode}` : "not run yet"} />
          <Stage
            done={false}
            label={alertActions.length > 0 ? "Awaiting approval" : "No action queued"}
            detail={alertActions.length > 0
              ? alertActions.map((a) => `${a.action_type} ${a.target_value ?? ""}`).join(", ")
              : "run the decision engine to queue remediation"}
            last
          />
        </ol>

        {can("detection", "run") && (
          <div className="mt-3 flex flex-wrap gap-2">
            <Btn
              onClick={() => analyze.mutate({ id: alert.id }, { onSuccess: setAnalysis })}
              busy={analyze.isPending}
              label="Analyze"
            />
            <Btn
              onClick={() => decide.mutate(
                { id: alert.id, mode, createActions: true },
                { onSuccess: setDecision },
              )}
              busy={decide.isPending}
              label="Decide & queue"
              primary
            />
            {alertActions.length > 0 && (
              <Link
                to="/alerts"
                className="border border-rule-2 px-3 py-1.5 text-sm font-semibold text-ink hover:border-ink-3"
              >
                Review queue
              </Link>
            )}
          </div>
        )}
      </div>

      <p className="data p-3.5 text-xs leading-relaxed text-ink-3">
        guardrail · block_ip refuses internal and allowlisted ranges; disable_account refuses
        protected accounts. Nothing executes without approval in assisted mode.
      </p>
    </>
  );
}

/* ───────────────────────── primitives ──────────────────────── */

function Meta({ children, last }: { children: React.ReactNode; last?: boolean }) {
  return (
    <span className={cn("pr-2 mr-2", !last && "border-r border-rule-2")}>{children}</span>
  );
}

function Cell({ label, value, last }: { label: string; value: string; last?: boolean }) {
  return (
    <div className={cn("px-3.5 py-2.5", !last && "border-r border-rule")}>
      <dt className="eyebrow mb-1">{label}</dt>
      <dd className="data text-sm font-medium">{value}</dd>
    </div>
  );
}

function Stage({ done, label, detail, last }: { done: boolean; label: string; detail: string; last?: boolean }) {
  return (
    <li className="relative grid grid-cols-[14px_1fr] items-start gap-2.5 py-1.5">
      {!last && <span className="absolute left-[6.5px] top-4 h-full w-px bg-rule-2" aria-hidden />}
      <span className={cn(
        "z-10 mt-0.5 grid size-3.5 place-items-center border bg-void",
        done ? "border-ok" : "border-ink-3",
      )}>
        {done && <Check className="size-2 text-ok" strokeWidth={3} />}
      </span>
      <span>
        <span className="block text-sm">{label}</span>
        <span className="data block text-2xs text-ink-3">{detail}</span>
      </span>
    </li>
  );
}

function Btn({ onClick, busy, label, primary }: { onClick: () => void; busy: boolean; label: string; primary?: boolean }) {
  return (
    <button
      onClick={onClick}
      disabled={busy}
      className={cn(
        "px-3 py-1.5 text-sm font-semibold disabled:opacity-50",
        primary ? "bg-ink text-void hover:bg-ink/90" : "border border-rule-2 text-ink hover:border-ink-3",
      )}
    >
      {busy ? "Working…" : label}
    </button>
  );
}

function Muted({ children }: { children: React.ReactNode }) {
  return <p className="p-3.5 text-sm text-ink-3">{children}</p>;
}
