import { Annotation, END, START, StateGraph } from "@langchain/langgraph";
import { aiAvailable, callGemini, describeModelError, type StructuredAgent } from "./model";
import { DETECTOR_SYSTEM, EXPLAINER_SYSTEM, detectorPrompt, explainerPrompt } from "./prompts";
import {
  buildAiReport,
  buildAnalystReport,
  buildPatternReport,
  isLinkOnly,
  rate,
  type ReportContext,
} from "./report";
import { scanSignals } from "./signals";
import { siteChecksEnabled, verifySite } from "./site/verify";
import {
  DetectionSchema,
  ExplanationSchema,
  type Detection,
  type Report,
  type Signal,
  type SiteReport,
} from "./types";

/**
 * The PhishGuard workflow:
 *
 *   START → scan → verify_site → detect → explain → END
 *                       │           │
 *                       └───────────┴──→ pattern_report → END
 *
 * `scan` is deterministic. `verify_site` checks the main link against outside
 * sources. `detect` and `explain` are model calls. If no API key is set, or
 * the detector fails, the report is built without a model.
 */

const State = Annotation.Root({
  input: Annotation<string>,
  signals: Annotation<Signal[]>,
  site: Annotation<SiteReport | null>,
  detection: Annotation<Detection | null>,
  report: Annotation<Report | null>,
  aiError: Annotation<string | null>,
});
type GraphState = typeof State.State;

/** What the workflow needs from the outside world. Swappable in tests. */
export type GraphDeps = {
  callAgent: StructuredAgent;
  aiAvailable: () => boolean;
  /** Verifies the main link, or returns null when there is none. */
  verifySite: (input: string, signals: Signal[]) => Promise<SiteReport | null>;
};

const defaultDeps: GraphDeps = {
  callAgent: callGemini,
  aiAvailable,
  verifySite: async (input, signals) => (siteChecksEnabled() ? verifySite(input, signals) : null),
};

export function createPhishGuardGraph(overrides: Partial<GraphDeps> = {}) {
  const { callAgent, aiAvailable, verifySite } = { ...defaultDeps, ...overrides };

  const scan = (state: GraphState) => ({ signals: scanSignals(state.input) });

  /** Website checks are extra evidence: if they fail, the report goes ahead without them. */
  async function verify(state: GraphState) {
    try {
      return { site: await verifySite(state.input, state.signals) };
    } catch (err) {
      console.error("[phishguard] website check failed:", err);
      return { site: null };
    }
  }

  /** Agent 1: the security analyst. */
  async function detect(state: GraphState) {
    try {
      const detection = await callAgent({
        system: DETECTOR_SYSTEM,
        user: detectorPrompt(state.input, state.signals, state.site),
        schema: DetectionSchema,
      });
      return { detection };
    } catch (err) {
      console.error("[phishguard] detector failed:", err);
      return { detection: null, aiError: describeModelError(err) };
    }
  }

  const contextOf = (state: GraphState): ReportContext => ({
    site: state.site,
    linkOnly: isLinkOnly(state.input),
    aiError: state.aiError,
  });

  /** Agent 2: the educator. It words the report but cannot change the verdict. */
  async function explain(state: GraphState) {
    const detection = state.detection!;
    const context = contextOf(state);
    try {
      // The explainer is told the final verdict, after the website check is applied.
      const rated = rate(detection.verdict, detection.riskScore, context);
      const explanation = await callAgent({
        system: EXPLAINER_SYSTEM,
        user: explainerPrompt(state.input, { ...detection, ...rated }, state.site),
        schema: ExplanationSchema,
      });
      return { report: buildAiReport(detection, explanation, context) };
    } catch (err) {
      console.error("[phishguard] explainer failed:", err);
      return { report: buildAnalystReport(detection, context) };
    }
  }

  const patternReport = (state: GraphState) => ({
    report: buildPatternReport(state.signals, contextOf(state)),
  });

  return new StateGraph(State)
    .addNode("scan", scan)
    .addNode("verify_site", verify)
    .addNode("detect", detect)
    .addNode("explain", explain)
    .addNode("pattern_report", patternReport)
    .addEdge(START, "scan")
    .addEdge("scan", "verify_site")
    .addConditionalEdges("verify_site", () => (aiAvailable() ? "detect" : "pattern_report"), [
      "detect",
      "pattern_report",
    ])
    .addConditionalEdges("detect", (state) => (state.detection ? "explain" : "pattern_report"), [
      "explain",
      "pattern_report",
    ])
    .addEdge("explain", END)
    .addEdge("pattern_report", END)
    .compile();
}

export const phishGuardGraph = createPhishGuardGraph();
