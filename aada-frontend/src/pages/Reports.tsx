import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { FileText, Download, FileJson, Sparkles } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useReports, useReport, useGenerateReport } from "@/hooks/queries";
import { api } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

export default function Reports() {
  const [params] = useSearchParams();
  const generateAlertId = params.get("generate");
  const { data: reports, isLoading } = useReports();
  const generate = useGenerateReport();
  const [selected, setSelected] = useState<string | null>(null);

  // Auto-generate when arriving from an investigation with ?generate=<alertId>.
  useEffect(() => {
    if (generateAlertId) generate.mutate(generateAlertId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [generateAlertId]);

  return (
    <div className="space-y-5 p-4">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Incident Reports</h1>
        <p className="text-sm text-muted-foreground">AI-authored reports · export PDF or JSON</p>
      </div>

      {generate.isPending && (
        <Card><CardContent className="flex items-center gap-2 py-4 text-sm text-primary">
          <Sparkles className="size-4 animate-pulse" /> Generating report…
        </CardContent></Card>
      )}

      <div className="grid gap-5 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader><CardTitle>Reports</CardTitle></CardHeader>
          <CardContent className="space-y-1.5">
            {isLoading ? Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-14 w-full" />)
              : (reports ?? []).length === 0 ? <p className="text-sm text-muted-foreground">No reports yet. Generate one from an investigation.</p>
              : (reports ?? []).map((r) => (
                <button
                  key={r.id}
                  onClick={() => setSelected(r.id)}
                  className={`w-full rounded-md border p-3 text-left transition-colors ${selected === r.id ? "border-primary/50 bg-primary/10" : "border-border/60 hover:bg-accent/40"}`}
                >
                  <div className="flex items-start gap-2">
                    <FileText className="mt-0.5 size-4 text-primary" />
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium">{r.title}</p>
                      <p className="text-xs text-muted-foreground">{fmtDate(r.created_at)}</p>
                    </div>
                  </div>
                </button>
              ))}
          </CardContent>
        </Card>

        <div className="lg:col-span-2">
          {selected ? <ReportPreview id={selected} /> : (
            <Card><CardContent className="py-16 text-center text-muted-foreground">
              Select a report to preview.
            </CardContent></Card>
          )}
        </div>
      </div>
    </div>
  );
}

function ReportPreview({ id }: { id: string }) {
  const { data: r, isLoading } = useReport(id);
  if (isLoading || !r) return <Card><CardContent className="py-10"><Skeleton className="h-64 w-full" /></CardContent></Card>;

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between">
        <div>
          <CardTitle>{r.title}</CardTitle>
          <p className="mt-1 font-mono text-xs text-muted-foreground">{r.report_id} · {r.severity} · {r.status}</p>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" asChild>
            <a href={api.reportPdfUrl(id)} target="_blank" rel="noreferrer"><Download className="size-4" /> PDF</a>
          </Button>
          <Button size="sm" variant="outline" asChild>
            <a href={api.reportJsonUrl(id)} target="_blank" rel="noreferrer"><FileJson className="size-4" /> JSON</a>
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-5 text-sm">
        <Block title="Executive Summary"><p className="leading-relaxed text-muted-foreground">{r.executive_summary}</p></Block>

        <Block title="Timeline">
          <ol className="space-y-1.5">
            {r.timeline.map((t, i) => (
              <li key={i} className="flex gap-2 text-xs">
                <span className="w-36 shrink-0 font-mono text-muted-foreground">{t.timestamp ? new Date(t.timestamp).toLocaleString() : "—"}</span>
                <Badge variant="outline" className="h-5">{t.category}</Badge>
                <span>{t.title}</span>
              </li>
            ))}
          </ol>
        </Block>

        <div className="grid gap-5 sm:grid-cols-2">
          <Block title="IOCs">
            <IOCList label="IPs" items={r.iocs.ips} />
            <IOCList label="Domains" items={r.iocs.domains} />
            <IOCList label="Hashes" items={r.iocs.hashes} />
            <IOCList label="Accounts" items={r.iocs.accounts} />
          </Block>
          <Block title="MITRE ATT&CK">
            {r.mitre.map((m) => (
              <p key={m.technique_id} className="text-xs"><span className="font-mono text-primary">{m.technique_id}</span> {m.name}{m.tactic ? ` · ${m.tactic}` : ""}</p>
            ))}
          </Block>
        </div>

        <Block title="Root Cause"><p className="leading-relaxed text-muted-foreground">{r.root_cause}</p></Block>
        <Block title="Recommendations">
          <ul className="space-y-1">
            {r.recommendations.map((rec, i) => (
              <li key={i} className="text-xs"><Badge variant="outline" className="mr-2 capitalize">{rec.priority}</Badge>{rec.title}</li>
            ))}
          </ul>
        </Block>
      </CardContent>
    </Card>
  );
}

const Block = ({ title, children }: { title: string; children: React.ReactNode }) => (
  <div>
    <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-primary">{title}</p>
    {children}
  </div>
);
const IOCList = ({ label, items }: { label: string; items: string[] }) =>
  items.length ? (
    <div className="mb-1.5">
      <span className="text-xs text-muted-foreground">{label}:</span>{" "}
      {items.map((i) => <span key={i} className="font-mono text-xs">{i} </span>)}
    </div>
  ) : null;
