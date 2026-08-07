import { useMemo } from "react";
import { cn } from "@/lib/utils";
import type { SecurityEvent, Severity } from "@/lib/types";

const BUCKETS = 72;

const SEV_RANK: Record<Severity, number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};
const SEV_CLASS: Record<Severity, string> = {
  info: "bg-ink-3/40",
  low: "bg-sev-low/70",
  medium: "bg-sev-medium/80",
  high: "bg-sev-high",
  critical: "bg-sev-critical",
};

/**
 * Event volume over the window the data actually covers, bucketed and colored by
 * the worst severity in each bucket — so an attack reads as a spike against
 * benign chatter rather than a number in a tile.
 */
export function EventSpine({ events, loading }: { events: SecurityEvent[]; loading?: boolean }) {
  const { bars, span, counts } = useMemo(() => {
    const stamped = events
      .map((e) => ({ t: Date.parse(e.created_at ?? e.ingested_at), sev: e.severity }))
      .filter((e) => Number.isFinite(e.t));

    const counts = { critical: 0, high: 0, benign: 0 };
    for (const e of stamped) {
      if (e.sev === "critical") counts.critical++;
      else if (e.sev === "high") counts.high++;
      else counts.benign++;
    }

    if (stamped.length === 0) return { bars: [], span: null, counts };

    const max = Math.max(...stamped.map((e) => e.t));
    // Never collapse to a zero-width window when every event lands in one instant.
    const min = Math.min(...stamped.map((e) => e.t), max - 60 * 60 * 1000);
    const width = Math.max(max - min, 1);

    const buckets = Array.from({ length: BUCKETS }, () => ({ n: 0, worst: "info" as Severity }));
    for (const e of stamped) {
      const i = Math.min(BUCKETS - 1, Math.floor(((e.t - min) / width) * BUCKETS));
      buckets[i].n += 1;
      if (SEV_RANK[e.sev] > SEV_RANK[buckets[i].worst]) buckets[i].worst = e.sev;
    }
    const peak = Math.max(...buckets.map((b) => b.n), 1);

    return {
      bars: buckets.map((b) => ({
        pct: b.n === 0 ? 0 : Math.max(6, (b.n / peak) * 100),
        sev: b.worst,
        n: b.n,
      })),
      span: { min, max },
      counts,
    };
  }, [events]);

  return (
    <section className="shrink-0 border-b border-rule bg-pane px-3.5 pb-2.5 pt-3">
      <div className="mb-2.5 flex items-baseline gap-3">
        <span className="eyebrow">Event activity</span>
        <span className="data text-xs text-ink-2">{events.length.toLocaleString()} events</span>
        <div className="ml-auto flex gap-3.5">
          <Key className="bg-sev-critical" label={`crit ${counts.critical}`} />
          <Key className="bg-sev-high" label={`high ${counts.high}`} />
          <Key className="bg-ink-3" label={`benign ${counts.benign.toLocaleString()}`} />
        </div>
      </div>

      <div className="flex h-[46px] items-end gap-[2px]" role="img" aria-label="Event volume over time">
        {loading || bars.length === 0
          ? Array.from({ length: BUCKETS }).map((_, i) => (
              <span key={i} className="min-h-[2px] flex-1 bg-rule" style={{ height: "12%" }} />
            ))
          : bars.map((b, i) => (
              <span
                key={i}
                title={`${b.n} event${b.n === 1 ? "" : "s"}`}
                // Empty buckets keep a visible baseline tick so the axis reads as a
                // continuous timeline rather than a broken chart.
                className={cn("min-h-[2px] flex-1", b.n === 0 ? "bg-rule-2" : SEV_CLASS[b.sev])}
                style={{ height: b.n === 0 ? "9%" : `${b.pct}%` }}
              />
            ))}
      </div>

      <div className="data mt-1.5 flex justify-between text-2xs text-ink-3">
        <span>{span ? fmt(span.min) : "—"}</span>
        <span>{span ? fmt(span.max) : "now"}</span>
      </div>
    </section>
  );
}

function Key({ className, label }: { className: string; label: string }) {
  return (
    <span className="data flex items-center gap-1.5 text-2xs text-ink-3">
      <i className={cn("size-1.5", className)} aria-hidden />
      {label}
    </span>
  );
}

function fmt(ms: number) {
  return new Date(ms).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}
