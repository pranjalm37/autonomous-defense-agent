import { useState } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { Brain, Scale, Check, X, Cpu, ShieldAlert, FileText } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge, StatusText } from "@/components/SeverityBadge";
import {
  useAlert, useAlerts, useAnalyzeAlert, useDecideAlert, useActions, useReviewAction,
} from "@/hooks/queries";
import { usePermissions } from "@/hooks/useAuth";
import { useAppStore } from "@/store/appStore";
import type { AIAnalysis, Decision } from "@/lib/types";

export default function Investigations() {
  const [params, setParams] = useSearchParams();
  const alertId = params.get("alert") ?? "";
  if (!alertId) return <AlertPicker onPick={(id) => setParams({ alert: id })} />;
  return <Investigation alertId={alertId} />;
}

function Investigation({ alertId }: { alertId: string }) {
  const { data: alert } = useAlert(alertId);
  const mode = useAppStore((s) => s.defenseMode);
  const { can } = usePermissions();
  const analyze = useAnalyzeAlert();
  const decide = useDecideAlert();
  const [analysis, setAnalysis] = useState<AIAnalysis | null>(null);
  const [decision, setDecision] = useState<Decision | null>(null);

  const runAnalyze = () =>
    analyze.mutate({ id: alertId, createActions: false }, { onSuccess: setAnalysis });
  const runDecide = () =>
    decide.mutate({ id: alertId, mode, createActions: true }, { onSuccess: setDecision });

  if (!alert) return <div className="text-muted-foreground">Loading investigation…</div>;

  return (
    <div className="space-y-5">
      <Link to="/alerts" className="text-xs text-primary hover:underline">← All alerts</Link>

      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <h1 className="text-xl font-bold tracking-tight">{alert.title}</h1>
          </div>
          <p className="mt-1 font-mono text-xs text-muted-foreground">
            {alert.source_ip ?? "—"} → {alert.dest_ip ?? "—"} · {alert.hostname ?? "—"} · user {alert.affected_user ?? "—"} · <StatusText status={alert.status} />
          </p>
        </div>
        <div className="flex gap-2">
          {can("analysis", "run") && (
            <Button onClick={runAnalyze} disabled={analyze.isPending}>
              <Brain className="size-4" /> {analyze.isPending ? "Analyzing…" : "AI analyze"}
            </Button>
          )}
          {can("decision", "run") && (
            <Button variant="secondary" onClick={runDecide} disabled={decide.isPending}>
              <Scale className="size-4" /> {decide.isPending ? "Deciding…" : `Decide (${mode})`}
            </Button>
          )}
          {can("reports", "generate") && (
            <Button variant="outline" asChild>
              <Link to={`/reports?generate=${alertId}`}><FileText className="size-4" /> Report</Link>
            </Button>
          )}
        </div>
      </div>

      <div className="grid gap-5 lg:grid-cols-3">
        <div className="space-y-5 lg:col-span-2">
          {analysis ? <AnalysisPanel a={analysis} /> : (
            <Card><CardContent className="py-12 text-center text-muted-foreground">
              <Cpu className="mx-auto mb-2 size-8 opacity-50" />
              Run <span className="text-primary">AI analyze</span> to generate the reasoning chain, MITRE mapping, and recommended actions.
            </CardContent></Card>
          )}
        </div>

        <div className="space-y-5">
          {decision && <DecisionPanel d={decision} />}
          <ApprovalPanel alertId={alertId} />
        </div>
      </div>
    </div>
  );
}

function AnalysisPanel({ a }: { a: AIAnalysis }) {
  return (
    <>
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle>AI Analysis</CardTitle>
          <div className="flex items-center gap-2">
            <Badge variant={a.is_true_positive ? "destructive" : "muted"}>
              {a.is_true_positive ? "true positive" : "false positive"}
            </Badge>
            <Badge variant="default">{Math.round(a.confidence * 100)}% conf</Badge>
            <Badge variant="outline">risk {a.risk_score}</Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          <Section title="Executive summary">{a.executive_summary}</Section>
          <Section title="Attack narrative">{a.attack_narrative}</Section>
          <Section title="Technical analysis">{a.technical_analysis}</Section>
        </CardContent>
      </Card>

      <div className="grid gap-5 sm:grid-cols-2">
        <Card>
          <CardHeader><CardTitle className="text-sm">MITRE ATT&CK</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {a.mitre_techniques.map((t) => (
              <div key={t.technique_id} className="text-sm">
                <span className="font-mono text-primary">{t.technique_id}</span> {t.name}
                <span className="text-muted-foreground"> · {t.tactic}</span>
              </div>
            ))}
            {a.mitre_techniques.length === 0 && <Muted />}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm">Indicators</CardTitle></CardHeader>
          <CardContent className="space-y-1">
            {a.iocs.map((i) => <p key={i} className="font-mono text-xs">{i}</p>)}
            {a.iocs.length === 0 && <Muted />}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader><CardTitle className="text-sm">Recommended actions</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {a.recommended_actions.map((r, i) => (
            <div key={i} className="flex items-start gap-2 rounded-md border border-border/60 p-2.5">
              <Badge variant="outline" className="capitalize">{r.priority}</Badge>
              <div className="text-sm">
                <p className="font-medium">{r.title} <span className="font-mono text-xs text-muted-foreground">({r.action_type} → {r.target})</span></p>
                <p className="text-xs text-muted-foreground">{r.rationale}</p>
              </div>
            </div>
          ))}
          {a.recommended_actions.length === 0 && <Muted />}
        </CardContent>
      </Card>
    </>
  );
}

function DecisionPanel({ d }: { d: Decision }) {
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="text-sm">Decision</CardTitle>
        <Badge variant={d.is_false_positive ? "muted" : "destructive"}>{d.verdict}</Badge>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div className="flex gap-2">
          <Badge variant="outline">risk {d.risk_score}</Badge>
          <Badge variant="default">{Math.round(d.confidence_score * 100)}% conf</Badge>
          <Badge variant="secondary" className="capitalize">{d.mode}</Badge>
        </div>
        <p className="text-muted-foreground">{d.rationale}</p>
        <div className="space-y-1.5">
          {d.action_decisions.map((ad, i) => (
            <div key={i} className="flex items-center justify-between rounded border border-border/60 px-2 py-1.5 text-xs">
              <span className="font-mono">{ad.action_type} → {ad.target}</span>
              <Badge variant={dispVariant(ad.disposition)}>{ad.disposition.replace("_", " ")}</Badge>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function ApprovalPanel({ alertId }: { alertId: string }) {
  const { data: pending } = useActions("pending");
  const { approve, deny } = useReviewAction();
  const { can } = usePermissions();
  const canReview = can("actions", "approve");
  const mine = (pending ?? []).filter((a) => a.alert_id === alertId);

  return (
    <Card>
      <CardHeader><CardTitle className="text-sm flex items-center gap-2"><ShieldAlert className="size-4 text-primary" /> Approval queue</CardTitle></CardHeader>
      <CardContent className="space-y-2">
        {mine.length === 0 && <Muted text="No actions pending for this alert." />}
        {mine.map((a) => (
          <div key={a.id} className="rounded-md border border-border/60 p-2.5">
            <p className="text-sm font-medium font-mono">{a.action_type} → {a.target_value}</p>
            <p className="mb-2 text-xs text-muted-foreground">{a.ai_justification}</p>
            {canReview ? (
              <div className="flex gap-2">
                <Button size="sm" variant="success" onClick={() => approve.mutate({ id: a.id })}><Check className="size-3.5" /> Approve</Button>
                <Button size="sm" variant="outline" onClick={() => deny.mutate({ id: a.id })}><X className="size-3.5" /> Reject</Button>
              </div>
            ) : (
              <p className="text-xs italic text-muted-foreground">Viewer role — approval requires an analyst.</p>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function AlertPicker({ onPick }: { onPick: (id: string) => void }) {
  const { data } = useAlerts({ limit: 50 });
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold tracking-tight">Investigations</h1>
      <p className="text-sm text-muted-foreground">Select an alert to investigate.</p>
      <Card><CardContent className="space-y-1 p-3">
        {(data?.items ?? []).map((a) => (
          <button key={a.id} onClick={() => onPick(a.id)} className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-left hover:bg-accent/40">
            <SeverityBadge severity={a.severity} />
            <span className="flex-1 text-sm font-medium">{a.title}</span>
            <span className="font-mono text-xs text-muted-foreground">{a.source_ip}</span>
          </button>
        ))}
      </CardContent></Card>
    </div>
  );
}

const Section = ({ title, children }: { title: string; children: React.ReactNode }) => (
  <div>
    <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-primary">{title}</p>
    <p className="leading-relaxed text-muted-foreground">{children}</p>
  </div>
);
const Muted = ({ text = "None" }: { text?: string }) => <p className="text-sm text-muted-foreground">{text}</p>;
const dispVariant = (d: string) =>
  d === "auto_execute" ? "destructive" : d === "suppress" ? "muted" : "default";
