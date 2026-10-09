import type { SiteCheck, SiteReport } from "@/lib/phishguard/types";
import { CARD, MUTED, OUTCOME_STYLE, SITE_STYLE } from "./styles";

/** "+10", "−25", or a dash for a check that could not run. */
function impactText(check: SiteCheck): { shown: string; spoken: string } {
  if (check.outcome === "unavailable") return { shown: "–", spoken: "no effect on the score" };
  if (check.impact > 0) return { shown: `+${check.impact}`, spoken: `adds ${check.impact} points` };
  if (check.impact < 0)
    return { shown: `−${-check.impact}`, spoken: `removes ${-check.impact} points` };
  return { shown: "0", spoken: "no effect on the score" };
}

function CheckRow({ check }: { check: SiteCheck }) {
  const outcome = OUTCOME_STYLE[check.outcome];
  const impact = impactText(check);
  return (
    <li className="py-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-medium ${outcome.badge}`}>
          {outcome.label}
        </span>
        <h5 className="text-sm font-semibold">{check.label}</h5>
        <span className="ml-auto text-sm font-semibold tabular-nums">
          <span aria-hidden="true">{impact.shown}</span>
          <span className="sr-only">{impact.spoken}</span>
        </span>
      </div>
      <p className="mt-1 text-sm text-slate-800 dark:text-slate-200">{check.summary}</p>
      <p className={`mt-1 text-xs ${MUTED}`}>{check.evidence}</p>
      {check.source && (
        <a
          href={check.source.url}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-1 inline-block text-xs font-medium text-teal-700 underline dark:text-teal-400"
        >
          {check.source.name}
          <span className="sr-only"> (opens in a new tab)</span>
        </a>
      )}
    </li>
  );
}

/**
 * The website verification result: classification, trust score, recommended
 * action, and every check with its evidence and its effect on the score. The
 * checked address is shown as text only, never as a link.
 */
export function SiteCheckCard({ site }: { site: SiteReport }) {
  const style = SITE_STYLE[site.classification];
  return (
    <section aria-labelledby="site-heading" className={`${CARD} p-5`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 id="site-heading" className="text-lg font-semibold">
          Website check
        </h3>
        <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${style.badge}`}>
          {style.label}
        </span>
      </div>
      <p className={`mt-1 break-all font-mono text-sm ${MUTED}`}>{site.domain}</p>

      <div className="mt-4 flex items-baseline justify-between gap-4">
        <p className="text-sm font-medium">Trust score</p>
        <p className="text-sm tabular-nums">{site.trustScore}/100</p>
      </div>
      <div
        role="meter"
        aria-label="Trust score"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={site.trustScore}
        aria-valuetext={`${site.trustScore} out of 100: ${style.label}`}
        className="mt-2 h-1.5 overflow-hidden rounded-full bg-black/10 dark:bg-white/10"
      >
        <div className={`h-full ${style.bar}`} style={{ width: `${site.trustScore}%` }} />
      </div>
      {site.scoreNote && <p className={`mt-1 text-xs ${MUTED}`}>{site.scoreNote}</p>}

      <p className="mt-4 font-semibold">{site.headline}</p>
      <p className="mt-1 text-sm text-slate-700 dark:text-slate-300">{site.summary}</p>
      <p className="mt-3 rounded-lg bg-slate-100 p-3 text-sm dark:bg-slate-800">
        <span className="font-semibold">Recommended action: </span>
        {site.recommendedAction}
      </p>

      <h4 className="mt-5 text-sm font-semibold">How the score was reached</h4>
      <p className={`mt-1 text-xs ${MUTED}`}>
        The score starts at 50. Each check adds or removes the points shown. A check that could not
        run changes nothing.
      </p>
      <ul className="mt-2 divide-y divide-slate-200 dark:divide-slate-800">
        {site.checks.map((check) => (
          <CheckRow key={check.id} check={check} />
        ))}
      </ul>

      {site.redirectChain.length > 1 && (
        <>
          <h4 className="mt-4 text-sm font-semibold">Where the link leads</h4>
          <ol className={`mt-2 list-decimal space-y-1 pl-5 font-mono text-xs ${MUTED}`}>
            {site.redirectChain.map((address, index) => (
              <li key={index} className="break-all">
                {address}
              </li>
            ))}
          </ol>
        </>
      )}

      <p className={`mt-4 text-xs ${MUTED}`}>
        A good rating doesn&apos;t guarantee a website is legitimate, and a missing profile
        doesn&apos;t mean it is a scam.
      </p>
    </section>
  );
}
