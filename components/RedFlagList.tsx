import type { RedFlag } from "@/lib/phishguard/types";
import { MUTED, SEVERITY_STYLE, flagId } from "./styles";

type Props = {
  redFlags: RedFlag[];
  activeFlag: number | null;
  onActiveFlagChange: (flag: number | null) => void;
};

/** One card per warning sign: what was found, the quote, and why it matters. */
export function RedFlagList({ redFlags, activeFlag, onActiveFlagChange }: Props) {
  return (
    <ol className="mt-4 space-y-3">
      {redFlags.map((flag, index) => {
        const severity = SEVERITY_STYLE[flag.severity];
        return (
          <li
            key={index}
            id={flagId(index)}
            tabIndex={-1}
            onMouseEnter={() => onActiveFlagChange(index)}
            onMouseLeave={() => onActiveFlagChange(null)}
            className={`scroll-mt-6 rounded-xl border bg-white p-4 dark:bg-slate-900 ${
              activeFlag === index ? "border-teal-600" : "border-slate-200 dark:border-slate-800"
            }`}
          >
            <div className="flex items-center gap-2">
              <span
                aria-hidden="true"
                className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-900 text-[11px] font-semibold text-white dark:bg-slate-100 dark:text-slate-900"
              >
                {index + 1}
              </span>
              <h4 className="font-semibold">{flag.title}</h4>
              <span
                className={`ml-auto shrink-0 rounded-full px-2 py-0.5 text-xs font-medium ${severity.badge}`}
              >
                {severity.label}
              </span>
            </div>
            {flag.evidence && (
              <blockquote
                className={`mt-2 break-all border-l-2 border-slate-300 pl-3 font-mono text-xs dark:border-slate-700 ${MUTED}`}
              >
                {flag.evidence}
              </blockquote>
            )}
            <p className="mt-2 text-sm text-slate-700 dark:text-slate-300">{flag.explanation}</p>
          </li>
        );
      })}
    </ol>
  );
}
