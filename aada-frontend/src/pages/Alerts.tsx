import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Search } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge, StatusText } from "@/components/SeverityBadge";
import { useAlerts } from "@/hooks/queries";
import { timeAgo } from "@/lib/utils";
import type { Severity } from "@/lib/types";

const SEVERITIES: (Severity | "all")[] = ["all", "critical", "high", "medium", "low", "info"];

export default function Alerts() {
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [q, setQ] = useState("");
  const navigate = useNavigate();
  const { data, isLoading } = useAlerts({ severity: severity === "all" ? undefined : severity, limit: 200 });

  const items = (data?.items ?? []).filter(
    (a) => !q || a.title.toLowerCase().includes(q.toLowerCase()) || (a.source_ip ?? "").includes(q),
  );

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Alerts</h1>
        <p className="text-sm text-muted-foreground">Triage queue — {data?.total ?? 0} total</p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative max-w-xs flex-1">
          <Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
          <Input className="pl-8" placeholder="Search title or IP…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="flex gap-1">
          {SEVERITIES.map((s) => (
            <Button
              key={s}
              size="sm"
              variant={severity === s ? "default" : "outline"}
              onClick={() => setSeverity(s)}
              className="capitalize"
            >
              {s}
            </Button>
          ))}
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Severity</TableHead>
                <TableHead>Title</TableHead>
                <TableHead>Source IP</TableHead>
                <TableHead>Threat</TableHead>
                <TableHead>Confidence</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                Array.from({ length: 8 }).map((_, i) => (
                  <TableRow key={i}><TableCell colSpan={7}><Skeleton className="h-6 w-full" /></TableCell></TableRow>
                ))
              ) : items.length === 0 ? (
                <TableRow><TableCell colSpan={7} className="py-10 text-center text-muted-foreground">No alerts match.</TableCell></TableRow>
              ) : items.map((a) => (
                <TableRow
                  key={a.id}
                  className="cursor-pointer"
                  onClick={() => navigate(`/investigations?alert=${a.id}`)}
                >
                  <TableCell><SeverityBadge severity={a.severity} /></TableCell>
                  <TableCell className="font-medium">{a.title}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{a.source_ip ?? "—"}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{a.threat_type ?? "—"}</TableCell>
                  <TableCell className="tabular-nums text-sm">
                    {a.ai_confidence != null ? `${Math.round(a.ai_confidence * 100)}%` : "—"}
                  </TableCell>
                  <TableCell><StatusText status={a.status} /></TableCell>
                  <TableCell className="text-xs text-muted-foreground">{timeAgo(a.created_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
