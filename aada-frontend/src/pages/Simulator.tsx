import { useNavigate } from "react-router-dom";
import { SimulatorLauncher } from "@/components/SimulatorLauncher";
import { useScenarios } from "@/hooks/queries";

/**
 * Full-page view of the same launcher used on the triage screen. Running a
 * scenario here jumps to triage with the resulting alert selected, so the
 * attack and the response stay one continuous flow.
 */
export default function Simulator() {
  const navigate = useNavigate();
  const { data: scenarios } = useScenarios();

  return (
    <div className="flex h-full flex-col">
      <div className="shrink-0 border-b border-rule bg-pane px-3.5 py-3">
        <h1 className="text-lg font-semibold tracking-tight">Attack simulator</h1>
        <p className="mt-0.5 max-w-[68ch] text-sm text-ink-2">
          Stage a known attack and watch the pipeline react to it. Each scenario writes
          synthetic log records through the normal ingestion path, then runs detection —
          the same code path a real feed takes.
        </p>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto bg-pane">
        <SimulatorLauncher onAlert={() => navigate("/")} />
      </div>

      <p className="data shrink-0 border-t border-rule px-3.5 py-2.5 text-2xs leading-relaxed text-ink-3">
        {scenarios?.length ?? 0} scenarios · simulated records only — staging performs no
        outbound network activity and executes no remediation. Anything detected still
        passes through the normal decision and approval gates.
      </p>
    </div>
  );
}
