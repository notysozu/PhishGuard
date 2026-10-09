import type { Report } from "@/lib/phishguard/types";
import { MUTED, VERDICT_STYLE } from "./styles";

/** Verdict label, risk meter, headline and summary. */
export function VerdictBanner({ report }: { report: Report }) {
  const style = VERDICT_STYLE[report.verdict];
  return (
    <div className={`rounded-2xl border p-5 ${style.banner}`}>
      <div className="flex items-baseline justify-between gap-4">
        <p className={`text-sm font-semibold uppercase tracking-wide ${style.text}`}>
          {style.label}
        </p>
        <p className="text-sm tabular-nums text-slate-700 dark:text-slate-300">
          Risk {report.riskScore}/100
        </p>
      </div>
      <div
        role="meter"
        aria-label="Risk score"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={report.riskScore}
        aria-valuetext={`${report.riskScore} out of 100: ${style.label}`}
        className="mt-2 h-1.5 overflow-hidden rounded-full bg-black/10 dark:bg-white/10"
      >
        <div className={`h-full ${style.bar}`} style={{ width: `${report.riskScore}%` }} />
      </div>
      <h2 id="result-heading" className="mt-4 text-xl font-semibold">
        {report.headline}
      </h2>
      <p className="mt-2 text-slate-700 dark:text-slate-300">{report.summary}</p>
      {report.notice && <p className={`mt-3 text-xs ${MUTED}`}>{report.notice}</p>}
    </div>
  );
}
