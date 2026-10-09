import { CATEGORY_COPY, fallbackGuidance } from "./copy";
import { scoreSignals } from "./signals";
import {
  verdictForScore,
  type Detection,
  type Explanation,
  type RedFlag,
  type Report,
  type Signal,
} from "./types";

// Pure functions that turn workflow results into the Report the clients render.

const clampScore = (score: number) => Math.max(0, Math.min(100, Math.round(score)));

const PATTERN_ONLY_CAVEAT =
  "This result comes from the built-in pattern scanner only, which can miss cleverly worded scams.";

/** Report built from scanner signals alone: no API key, or the detector failed. */
export function buildPatternReport(signals: Signal[], aiError?: string | null): Report {
  const riskScore = scoreSignals(signals);
  const verdict = verdictForScore(riskScore);
  return {
    verdict,
    riskScore,
    ...fallbackGuidance(verdict),
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
  };
}

/**
 * Report from both agents. The verdict, score and evidence always come from
 * the detector; the explainer only supplies wording, and any red flag that
 * points at a finding the detector did not report is dropped.
 */
export function buildAiReport(detection: Detection, explanation: Explanation): Report {
  const redFlags: RedFlag[] = [];
  for (const flag of explanation.redFlags) {
    const finding = detection.findings[flag.findingIndex];
    if (!finding) continue;
    redFlags.push({
      category: finding.category,
      severity: finding.severity,
      evidence: finding.evidence,
      title: flag.title,
      explanation: flag.explanation,
    });
  }
  return {
    verdict: detection.verdict,
    riskScore: clampScore(detection.riskScore),
    headline: explanation.headline,
    summary: explanation.summary,
    redFlags,
    reassuringSigns: detection.reassuringSigns,
    safetySteps: explanation.safetySteps,
    ifAlreadyClicked: explanation.ifAlreadyClicked,
    mode: "ai",
  };
}

/** Report when the detector succeeded but the explainer failed. */
export function buildAnalystReport(detection: Detection): Report {
  return {
    verdict: detection.verdict,
    riskScore: clampScore(detection.riskScore),
    ...fallbackGuidance(detection.verdict),
    redFlags: detection.findings.map((finding) => ({
      category: finding.category,
      severity: finding.severity,
      evidence: finding.evidence,
      title: CATEGORY_COPY[finding.category].title,
      explanation: finding.technicalReason,
    })),
    reassuringSigns: detection.reassuringSigns,
    mode: "ai",
    notice:
      "The plain-language explainer was unavailable, so this report uses the analyst's raw notes.",
  };
}
