import { useMemo } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle, ShieldAlert, Clock, Activity, Play, ChevronRight,
} from "lucide-react";
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, BarChart, Bar, XAxis, YAxis,
} from "recharts";
import { StatCard } from "@/components/StatCard";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useAlerts, useActions, useRunDetection } from "@/hooks/queries";
import { usePermissions } from "@/hooks/useAuth";
import { timeAgo } from "@/lib/utils";
import type { Severity } from "@/lib/types";

const SEV_COLORS: Record<Severity, string> = {
  critical: "hsl(350 89% 60%)", high: "hsl(25 95% 53%)", medium: "hsl(45 93% 47%)",
  low: "hsl(187 84% 53%)", info: "hsl(215 16% 47%)",
};

export default function Dashboard() {
  const { data: alerts, isLoading } = useAlerts({ limit: 100 });
  const { data: pending } = useActions("pending");
  const runDetection = useRunDetection();
  const { can } = usePermissions();

  const items = alerts?.items ?? [];
  const open = items.filter((a) => !["resolved", "false_positive"].includes(a.status));
  const critical = items.filter((a) => a.severity === "critical");

  const bySeverity = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const a of items) counts[a.severity] = (counts[a.severity] ?? 0) + 1;
    return (["critical", "high", "medium", "low", "info"] as Severity[])
      .map((s) => ({ name: s, value: counts[s] ?? 0 }))
      .filter((d) => d.value > 0);
  }, [items]);

  const byThreat = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const a of items) if (a.threat_type) counts[a.threat_type] = (counts[a.threat_type] ?? 0) + 1;
    return Object.entries(counts).map(([name, value]) => ({ name, value })).slice(0, 6);
  }, [items]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Command Center</h1>
          <p className="text-sm text-muted-foreground">Live posture across the environment</p>
        </div>
        {can("detection", "run") && (
          <Button onClick={() => runDetection.mutate(60)} disabled={runDetection.isPending}>
            <Play className="size-4" /> {runDetection.isPending ? "Running…" : "Run detection"}
          </Button>
        )}
      </div>

      {/* Stat row */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Open alerts" value={open.length} icon={AlertTriangle} tone="warning" />
        <StatCard label="Critical" value={critical.length} icon={ShieldAlert} tone="critical" />
        <StatCard label="Pending approvals" value={pending?.length ?? 0} icon={Clock} hint="awaiting human review" />
        <StatCard label="Total alerts" value={alerts?.total ?? 0} icon={Activity} tone="ok" />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Severity donut */}
        <Card className="lg:col-span-1">
          <CardHeader><CardTitle>Severity breakdown</CardTitle></CardHeader>
          <CardContent className="h-64">
            {isLoading ? <Skeleton className="h-full w-full" /> : bySeverity.length === 0 ? (
              <Empty />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={bySeverity} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={2}>
                    {bySeverity.map((d) => <Cell key={d.name} fill={SEV_COLORS[d.name as Severity]} />)}
                  </Pie>
                  <Tooltip contentStyle={tooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* Threat types bar */}
        <Card className="lg:col-span-2">
          <CardHeader><CardTitle>Top threat types</CardTitle></CardHeader>
          <CardContent className="h-64">
            {isLoading ? <Skeleton className="h-full w-full" /> : byThreat.length === 0 ? (
              <Empty />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={byThreat} layout="vertical" margin={{ left: 24 }}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="name" width={120} tick={{ fontSize: 12, fill: "hsl(215 16% 57%)" }} />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "hsl(187 84% 53% / 0.08)" }} />
                  <Bar dataKey="value" fill="hsl(187 84% 53%)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recent alerts */}
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle>Recent alerts</CardTitle>
          <Link to="/alerts" className="text-xs text-primary hover:underline">View all</Link>
        </CardHeader>
        <CardContent className="space-y-2">
          {isLoading ? (
            Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)
          ) : open.slice(0, 6).map((a) => (
            <Link
              key={a.id}
              to={`/investigations?alert=${a.id}`}
              className="flex items-center justify-between rounded-md border border-border/60 px-3 py-2.5 transition-colors hover:bg-accent/40"
            >
              <div className="flex items-center gap-3">
                <SeverityBadge severity={a.severity} />
                <div>
                  <p className="text-sm font-medium">{a.title}</p>
                  <p className="font-mono text-xs text-muted-foreground">
                    {a.source_ip ?? "—"} · {a.threat_type ?? "unknown"} · {timeAgo(a.created_at)}
                  </p>
                </div>
              </div>
              <ChevronRight className="size-4 text-muted-foreground" />
            </Link>
          ))}
          {!isLoading && open.length === 0 && <Empty text="No open alerts. All clear." />}
        </CardContent>
      </Card>
    </div>
  );
}

const tooltipStyle = {
  background: "hsl(223 56% 9%)", border: "1px solid hsl(200 50% 24%)",
  borderRadius: 8, fontSize: 12, color: "hsl(213 31% 91%)",
};
function Empty({ text = "No data" }: { text?: string }) {
  return <div className="flex h-full items-center justify-center text-sm text-muted-foreground">{text}</div>;
}
