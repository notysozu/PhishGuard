import { CATEGORY_COPY, fallbackGuidance } from "./copy";
import { extractUrls, scoreSignals } from "./signals";
import {
  RISK_THRESHOLDS,
  verdictForScore,
  type Detection,
  type Explanation,
  type RedFlag,
  type Report,
  type ReportVerdict,
  type Signal,
  type SiteReport,
} from "./types";

// Pure functions that turn workflow results into the Report the clients render.

const clampScore = (score: number) => Math.max(0, Math.min(100, Math.round(score)));

const PATTERN_ONLY_CAVEAT =
  "This result comes from the built-in pattern scanner only, which can miss cleverly worded scams.";

/** Everything besides the model's or scanner's own output that shapes a report. */
export type ReportContext = {
  /** Result of the website check, when the message has a link. */
  site?: SiteReport | null;
  /** True when the input is nothing but a web address. */
  linkOnly?: boolean;
  /** Why the AI could not be used, for the scanner-only notice. */
  aiError?: string | null;
};

/** True when the input is a single web address and nothing else. */
export function isLinkOnly(input: string): boolean {
  const urls = extractUrls(input);
  if (urls.length !== 1) return false;
  return !/[\p{L}\p{N}]/u.test(input.replace(urls[0], ""));
}

type Rating = { verdict: ReportVerdict; riskScore: number; siteNote?: string };

const between = (value: number, min: number, max: number) => Math.max(min, Math.min(max, value));

/** A bare address has no wording to judge, so the website check is the whole rating. */
function rateLink(site: SiteReport): Rating {
  const risk = 100 - site.trustScore;
  const { suspicious, dangerous } = RISK_THRESHOLDS;
  switch (site.classification) {
    case "confirmed_malicious":
      return { verdict: "dangerous", riskScore: Math.max(risk, 95) };
    case "suspicious":
      return { verdict: "suspicious", riskScore: between(risk, suspicious + 15, dangerous - 1) };
    case "unverified":
      return { verdict: "unverified", riskScore: risk };
    case "no_known_issues":
      return { verdict: "likely_safe", riskScore: Math.min(risk, suspicious - 1) };
  }
}

/**
 * Combines the message's own rating with the website check. For a message
 * with wording, the website can only raise concern, never lower it. A
 * threat-list hit always wins, so neither a clean-looking message nor the
 * model can talk a listed site down, and missing information alone never
 * makes something "dangerous".
 */
export function rate(
  verdict: ReportVerdict,
  riskScore: number,
  { site, linkOnly }: ReportContext = {},
): Rating {
  const score = clampScore(riskScore);
  if (site && linkOnly) return rateLink(site);
  switch (site?.classification) {
    case "confirmed_malicious":
      return {
        verdict: "dangerous",
        riskScore: Math.max(score, 95),
        siteNote:
          verdict === "dangerous"
            ? undefined
            : "Rated dangerous because the website is on a security threat list.",
      };
    case "suspicious":
      if (verdict === "dangerous" || verdict === "suspicious") return { verdict, riskScore: score };
      return {
        verdict: "suspicious",
        riskScore: Math.max(score, RISK_THRESHOLDS.suspicious + 15),
        siteNote: "Rated with caution because of the website check below.",
      };
    case "unverified":
      if (verdict !== "likely_safe") return { verdict, riskScore: score };
      return {
        verdict: "unverified",
        riskScore: score,
        siteNote:
          "The wording shows no warning signs, but the website could not be verified. See the website check below.",
      };
    default:
      return { verdict, riskScore: score };
  }
}

const joinNotes = (...notes: (string | undefined)[]) =>
  notes.filter(Boolean).join(" ") || undefined;

/** Report built without a model: no API key, or the detector failed. */
export function buildPatternReport(signals: Signal[], context: ReportContext = {}): Report {
  const { site, aiError } = context;
  const scanned = scoreSignals(signals);
  const { verdict, riskScore } = rate(verdictForScore(scanned), scanned, context);
  const guidance = fallbackGuidance(verdict);
  return {
    verdict,
    riskScore,
    ...guidance,
    // For a bare address, the website check has the specific finding and advice.
    ...(site && context.linkOnly
      ? {
          headline: `${site.headline}.`,
          summary: site.summary,
          safetySteps: [site.recommendedAction, ...guidance.safetySteps],
        }
      : {}),
    redFlags: signals.map((signal) => {
      const copy = CATEGORY_COPY[signal.category];
      return {
        category: signal.category,
        severity: signal.severity,
        evidence: signal.evidence,
        title: copy.title,
        explanation: `${signal.reason}. ${copy.why}`.trim(),
      };
    }),
    reassuringSigns: [],
    mode: "pattern",
    notice: aiError
      ? `AI analysis was unavailable (${aiError}). ${PATTERN_ONLY_CAVEAT}`
      : `No AI key is configured. ${PATTERN_ONLY_CAVEAT}`,
    site: site ?? undefined,
  };
}

/**
 * Report from both agents. The verdict, score and evidence always come from
 * the detector. The explainer only supplies wording: it cannot add a finding
 * the detector did not make, and a finding it skips is kept with the
 * analyst's own note rather than dropped.
 */
export function buildAiReport(
  detection: Detection,
  explanation: Explanation,
  context: ReportContext = {},
): Report {
  const wording = new Map(explanation.redFlags.map((flag) => [flag.findingIndex, flag]));
  const redFlags: RedFlag[] = detection.findings.map((finding, index) => {
    const explained = wording.get(index);
    return {
      category: finding.category,
      severity: finding.severity,
      evidence: finding.evidence,
      title: explained?.title ?? CATEGORY_COPY[finding.category].title,
      explanation: explained?.explanation ?? finding.technicalReason,
    };
  });
  const { verdict, riskScore, siteNote } = rate(detection.verdict, detection.riskScore, context);
  return {
    verdict,
    riskScore,
    headline: explanation.headline,
    summary: explanation.summary,
    redFlags,
    reassuringSigns: detection.reassuringSigns,
    safetySteps: explanation.safetySteps,
    ifAlreadyClicked: explanation.ifAlreadyClicked,
    mode: "ai",
    notice: siteNote,
    site: context.site ?? undefined,
  };
}

/** Report when the detector succeeded but the explainer failed. */
export function buildAnalystReport(detection: Detection, context: ReportContext = {}): Report {
  const { verdict, riskScore, siteNote } = rate(detection.verdict, detection.riskScore, context);
  return {
    verdict,
    riskScore,
    ...fallbackGuidance(verdict),
    redFlags: detection.findings.map((finding) => ({
      category: finding.category,
      severity: finding.severity,
      evidence: finding.evidence,
      title: CATEGORY_COPY[finding.category].title,
      explanation: finding.technicalReason,
    })),
    reassuringSigns: detection.reassuringSigns,
    mode: "ai",
    notice: joinNotes(
      "The plain-language explainer was unavailable, so this report uses the analyst's raw notes.",
      siteNote,
    ),
    site: context.site ?? undefined,
  };
}
