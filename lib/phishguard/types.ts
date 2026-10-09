import { z } from "zod";

export const MAX_INPUT_CHARS = 20_000;

/** Risk score (0-100) at which a message becomes "suspicious" / "dangerous". */
export const RISK_THRESHOLDS = { suspicious: 30, dangerous: 65 } as const;

export const CATEGORIES = [
  "urgency",
  "threat",
  "suspicious_link",
  "spoofed_sender",
  "credential_request",
  "payment_request",
  "too_good_to_be_true",
  "impersonation",
  "attachment",
  "generic_greeting",
  "other",
] as const;

export const SeveritySchema = z.enum(["low", "medium", "high"]);
export const VerdictSchema = z.enum(["dangerous", "suspicious", "likely_safe"]);
export const CategorySchema = z.enum(CATEGORIES);

export type Severity = z.infer<typeof SeveritySchema>;
export type Verdict = z.infer<typeof VerdictSchema>;
export type Category = z.infer<typeof CategorySchema>;

export function verdictForScore(score: number): Verdict {
  if (score >= RISK_THRESHOLDS.dangerous) return "dangerous";
  if (score >= RISK_THRESHOLDS.suspicious) return "suspicious";
  return "likely_safe";
}

/** A deterministic finding from the pattern scanner (no AI involved). */
export type Signal = {
  category: Category;
  severity: Severity;
  /** Exact substring of the user's input, so the UI can highlight it. */
  evidence: string;
  reason: string;
};

/** Agent 1 (detector) output: terse and technical. */
export const DetectionSchema = z.object({
  verdict: VerdictSchema,
  riskScore: z.number().describe("0 (certainly harmless) to 100 (certainly malicious)"),
  findings: z.array(
    z.object({
      category: CategorySchema,
      severity: SeveritySchema,
      evidence: z
        .string()
        .describe(
          "Short verbatim quote copied character-for-character from the message. Empty string if the finding is about something missing.",
        ),
      technicalReason: z.string(),
    }),
  ),
  reassuringSigns: z.array(z.string()).describe("Things that genuinely look legitimate, if any"),
});
export type Detection = z.infer<typeof DetectionSchema>;

/** Agent 2 (explainer) output: plain language for a non-technical reader. */
export const ExplanationSchema = z.object({
  headline: z.string().describe("One short sentence, max ~12 words"),
  summary: z.string().describe("2-3 calm, plain-language sentences"),
  redFlags: z.array(
    z.object({
      findingIndex: z.number().describe("Index into the detector's findings array"),
      title: z.string().describe("Plain-language label, max ~6 words"),
      explanation: z.string().describe("1-2 sentences: why scammers do this and how to spot it"),
    }),
  ),
  safetySteps: z.array(z.string()).describe("What to do right now, in order"),
  ifAlreadyClicked: z
    .array(z.string())
    .describe("Recovery steps if they already clicked, replied or paid"),
});
export type Explanation = z.infer<typeof ExplanationSchema>;

export type RedFlag = {
  category: Category;
  severity: Severity;
  evidence: string;
  title: string;
  explanation: string;
};

export type Report = {
  verdict: Verdict;
  riskScore: number;
  headline: string;
  summary: string;
  redFlags: RedFlag[];
  reassuringSigns: string[];
  safetySteps: string[];
  ifAlreadyClicked: string[];
  /** "ai" = both agents ran; "pattern" = offline pattern scanner only. */
  mode: "ai" | "pattern";
  notice?: string;
};

/** Workflow stages the web page shows progress for. */
export type ProgressStep = "scan" | "detect" | "explain";

/** One line of the NDJSON stream returned by POST /api/analyze. */
export type StreamEvent =
  | { type: "step"; step: ProgressStep }
  | { type: "report"; report: Report }
  | { type: "error"; message: string };
