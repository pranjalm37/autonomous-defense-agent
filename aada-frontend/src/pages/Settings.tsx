import { Eye, ShieldCheck, Bot, SlidersHorizontal, Plug, ScrollText } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { useRules, useAuditLogs } from "@/hooks/queries";
import { useAppStore } from "@/store/appStore";
import { cn, fmtDate } from "@/lib/utils";
import type { DecisionMode } from "@/lib/types";

const MODES: { value: DecisionMode; label: string; desc: string; icon: typeof Eye }[] = [
  { value: "monitor", label: "Monitor", desc: "Observe and recommend only. The agent never acts.", icon: Eye },
  { value: "assisted", label: "Assisted", desc: "Every action is queued for human approval (default).", icon: ShieldCheck },
  { value: "autonomous", label: "Autonomous", desc: "Auto-execute reversible, low-blast actions; escalate the rest.", icon: Bot },
];

export default function Settings() {
  return (
    <div className="space-y-5 p-4">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">Agent behavior, detection thresholds, integrations, audit</p>
      </div>

      <Tabs defaultValue="agent">
        <TabsList>
          <TabsTrigger value="agent"><Bot className="mr-1.5 size-4" /> Agent</TabsTrigger>
          <TabsTrigger value="thresholds"><SlidersHorizontal className="mr-1.5 size-4" /> Thresholds</TabsTrigger>
          <TabsTrigger value="integrations"><Plug className="mr-1.5 size-4" /> Integrations</TabsTrigger>
          <TabsTrigger value="audit"><ScrollText className="mr-1.5 size-4" /> Audit</TabsTrigger>
        </TabsList>

        <TabsContent value="agent"><AgentTab /></TabsContent>
        <TabsContent value="thresholds"><ThresholdsTab /></TabsContent>
        <TabsContent value="integrations"><IntegrationsTab /></TabsContent>
        <TabsContent value="audit"><AuditTab /></TabsContent>
      </Tabs>
    </div>
  );
}

function AgentTab() {
  const mode = useAppStore((s) => s.defenseMode);
  const setMode = useAppStore((s) => s.setDefenseMode);
  return (
    <Card>
      <CardHeader><CardTitle>Defense mode</CardTitle></CardHeader>
      <CardContent className="grid gap-3 sm:grid-cols-3">
        {MODES.map(({ value, label, desc, icon: Icon }) => (
          <button
            key={value}
            onClick={() => setMode(value)}
            className={cn(
              "rounded-lg border p-4 text-left transition-colors",
              mode === value ? "border-primary/50 bg-primary/10" : "border-border/60 hover:bg-accent/40",
            )}
          >
            <Icon className={cn("mb-2 size-5", mode === value ? "text-primary" : "text-muted-foreground")} />
            <p className="font-semibold">{label}</p>
            <p className="mt-1 text-xs text-muted-foreground">{desc}</p>
            {mode === value && <Badge className="mt-2">active</Badge>}
          </button>
        ))}
      </CardContent>
    </Card>
  );
}

function ThresholdsTab() {
  const { data: rules, isLoading } = useRules();
  return (
    <Card>
      <CardHeader><CardTitle>Detection rule thresholds</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        {isLoading ? Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)
          : (rules ?? []).map((r) => (
            <div key={r.rule_id} className="rounded-md border border-border/60 p-3">
              <div className="flex items-center justify-between">
                <p className="text-sm font-medium">{r.name}</p>
                <Badge variant="outline">{r.threat_type}</Badge>
              </div>
              <div className="mt-2 flex flex-wrap gap-3">
                {Object.entries(r.thresholds).map(([k, v]) => (
                  <span key={k} className="font-mono text-xs text-muted-foreground">{k}=<span className="text-foreground">{v}</span></span>
                ))}
              </div>
            </div>
          ))}
      </CardContent>
    </Card>
  );
}

const INTEGRATIONS = [
  { name: "VirusTotal", status: "configured" }, { name: "AbuseIPDB", status: "configured" },
  { name: "NVD", status: "active" }, { name: "ChromaDB (RAG)", status: "active" },
  { name: "OpenAI", status: "configured" }, { name: "MCP tools", status: "active" },
];
function IntegrationsTab() {
  return (
    <Card>
      <CardHeader><CardTitle>Integrations</CardTitle></CardHeader>
      <CardContent className="grid gap-2 sm:grid-cols-2">
        {INTEGRATIONS.map((i) => (
          <div key={i.name} className="flex items-center justify-between rounded-md border border-border/60 px-3 py-2.5">
            <span className="text-sm font-medium">{i.name}</span>
            <Badge variant={i.status === "active" ? "success" : "muted"}>{i.status}</Badge>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function AuditTab() {
  const { data: logs, isLoading } = useAuditLogs({ limit: 100 });
  return (
    <Card>
      <CardHeader><CardTitle>Audit log</CardTitle></CardHeader>
      <CardContent className="space-y-1">
        {isLoading ? Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)
          : (logs ?? []).length === 0 ? <p className="text-sm text-muted-foreground">No audit entries.</p>
          : (logs ?? []).map((l) => (
            <div key={l.id} className="flex items-center gap-3 border-b border-border/40 py-1.5 text-xs">
              <span className="w-36 shrink-0 font-mono text-muted-foreground">{fmtDate(l.created_at)}</span>
              <Badge variant="outline">{l.action.replace("action.", "")}</Badge>
              <span className="text-muted-foreground">{l.user_email ?? "system"}</span>
              <span className="font-mono text-muted-foreground">{l.resource_type}/{(l.resource_id ?? "").slice(0, 8)}</span>
            </div>
          ))}
      </CardContent>
    </Card>
  );
}
