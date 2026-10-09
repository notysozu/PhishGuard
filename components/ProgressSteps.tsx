import type { ProgressStep } from "@/lib/phishguard/types";

const STEPS: { id: ProgressStep; label: string }[] = [
  { id: "scan", label: "Scanning for known scam patterns" },
  { id: "detect", label: "Security analyst reviewing the message" },
  { id: "explain", label: "Writing your plain-language explanation" },
];

const STATE = {
  done: { dot: "bg-teal-600", text: "", srLabel: "done" },
  current: { dot: "animate-pulse bg-teal-500", text: "font-medium", srLabel: "in progress" },
  pending: {
    dot: "bg-slate-300 dark:bg-slate-700",
    text: "text-slate-600 dark:text-slate-400",
    srLabel: "not started",
  },
};

/** Shows which stage of the workflow is running. */
export function ProgressSteps({ current }: { current: ProgressStep }) {
  const currentIndex = STEPS.findIndex((step) => step.id === current);
  return (
    <ol className="space-y-2">
      {STEPS.map((step, index) => {
        const state =
          index < currentIndex
            ? STATE.done
            : index === currentIndex
              ? STATE.current
              : STATE.pending;
        return (
          <li
            key={step.id}
            aria-current={state === STATE.current ? "step" : undefined}
            className={`flex items-center gap-3 text-sm ${state.text}`}
          >
            <span aria-hidden="true" className={`h-2.5 w-2.5 rounded-full ${state.dot}`} />
            {step.label}
            <span className="sr-only">({state.srLabel})</span>
          </li>
        );
      })}
    </ol>
  );
}
