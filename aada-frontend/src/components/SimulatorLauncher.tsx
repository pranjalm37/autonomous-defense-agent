import { useState } from "react";
import { Check, Play, X } from "lucide-react";
import { useRunScenario, useScenarios } from "@/hooks/queries";
import { usePermissions } from "@/hooks/useAuth";
import { cn } from "@/lib/utils";
import type { SimulationResult } from "@/lib/types";

/**
 * Staged attacks, as a launcher rather than a card grid — it sits directly under
 * the alert stream so running one and watching the alert arrive is a single,
 * continuous action.
 */
export function SimulatorLauncher({ onAlert }: { onAlert?: (alertId: string) => void }) {
  const { data: scenarios, isLoading } = useScenarios();
  const run = useRunScenario();
  const { can } = usePermissions();

  const [active, setActive] = useState<string | null>(null);
  const [result, setResult] = useState<SimulationResult | null>(null);

  const mayRun = can("detection", "run");

  function launch(id: string) {
    setActive(id);
    setResult(null);
    run.mutate(id, {
      onSuccess: (r) => {
        setResult(r);
        if (r.alert_ids.length > 0) onAlert?.(r.alert_ids[0]);
      },
      onSettled: () => setActive(null),
    });
  }

  return (
    <div className="shrink-0 border-t border-rule">
      <div className="flex h-[34px] items-center gap-2.5 border-b border-rule px-3.5">
        <span className="eyebrow">Attack simulator</span>
        <span className="data text-xs text-ink-3">{scenarios?.length ?? 0} scenarios</span>
        <span className="data ml-auto text-2xs text-ink-3">
          {mayRun ? "stage & observe" : "read only"}
        </span>
      </div>

      {isLoading && <p className="p-3.5 text-sm text-ink-3">Loading scenarios…</p>}

      {scenarios?.map((s, i) => {
        const busy = active === s.id;
        const done = result?.scenario_id === s.id ? result : null;
        return (
          <div key={s.id} className="border-b border-rule last:border-b-0">
            <button
              onClick={() => launch(s.id)}
              disabled={!mayRun || run.isPending}
              title={mayRun ? s.description : "Requires the analyst or admin role"}
              className={cn(
                "grid w-full grid-cols-[auto_minmax(0,1fr)_auto_auto] items-center gap-3 px-3.5 py-2 text-left",
                mayRun ? "hover:bg-pane-2" : "cursor-not-allowed opacity-60",
              )}
            >
              <span className="data w-4 text-xs text-ink-3">{String(i + 1).padStart(2, "0")}</span>
              <span className="min-w-0">
                <span className="block truncate text-sm font-medium">
                  {s.name}
                  <span className="ml-2 font-normal text-ink-3">{s.description}</span>
                </span>
              </span>
              <span className="data text-2xs text-ink-3">{s.mitre}</span>
              <span
                className={cn(
                  "data flex items-center gap-1 border px-2 py-0.5 text-2xs font-bold tracking-wider",
                  busy ? "border-ink text-ink" : "border-rule-2 text-ink-3",
                )}
              >
                {busy ? "RUNNING" : <>RUN <Play className="size-2" fill="currentColor" strokeWidth={0} /></>}
              </span>
            </button>

            {done && (
              <ol className="border-t border-rule bg-pane-2 px-3.5 py-2">
                {done.stages.map((st) => (
                  <li key={st.stage} className="flex items-center gap-2 py-0.5">
                    <span
                      className={cn(
                        "grid size-3 place-items-center border",
                        st.ok ? "border-ok" : "border-sev-high",
                      )}
                    >
                      {st.ok ? (
                        <Check className="size-1.5 text-ok" strokeWidth={4} />
                      ) : (
                        <X className="size-1.5 text-sev-high" strokeWidth={4} />
                      )}
                    </span>
                    <span className="data flex-1 truncate text-2xs text-ink-2">{st.detail}</span>
                    <span className="data text-2xs text-ink-3">+{st.elapsed_ms.toFixed(0)}ms</span>
                  </li>
                ))}
                <li className="data mt-1 border-t border-rule pt-1 text-2xs text-ink-3">
                  {done.expected_rule_fired
                    ? `${done.expected_rule} fired · ${done.alerts_created} alert(s) · selected above`
                    : `${done.expected_rule} did not fire`}
                </li>
              </ol>
            )}
          </div>
        );
      })}

      {run.isError && (
        <p className="data border-t border-rule px-3.5 py-2 text-2xs text-sev-critical">
          Run failed — {(run.error as Error)?.message ?? "unknown error"}
        </p>
      )}
    </div>
  );
}
