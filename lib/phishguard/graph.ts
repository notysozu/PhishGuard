import { Annotation, END, START, StateGraph } from "@langchain/langgraph";
import { aiAvailable, callGemini, describeModelError, type StructuredAgent } from "./model";
import { DETECTOR_SYSTEM, EXPLAINER_SYSTEM, detectorPrompt, explainerPrompt } from "./prompts";
import { buildAiReport, buildAnalystReport, buildPatternReport } from "./report";
import { scanSignals } from "./signals";
import {
  DetectionSchema,
  ExplanationSchema,
  type Detection,
  type Report,
  type Signal,
} from "./types";

/**
 * The PhishGuard workflow:
 *
 *   START → scan → detect → explain → END
 *             │       │
 *             └───────┴──→ pattern_report → END
 *
 * `scan` is deterministic. `detect` and `explain` are model calls. If no API
 * key is set, or the detector fails, the report is built from scanner results.
 */

const State = Annotation.Root({
  input: Annotation<string>,
  signals: Annotation<Signal[]>,
  detection: Annotation<Detection | null>,
  report: Annotation<Report | null>,
  aiError: Annotation<string | null>,
});
type GraphState = typeof State.State;

/** What the workflow needs from the outside world. Swappable in tests. */
export type GraphDeps = {
  callAgent: StructuredAgent;
  aiAvailable: () => boolean;
};

const defaultDeps: GraphDeps = { callAgent: callGemini, aiAvailable };

export function createPhishGuardGraph({ callAgent, aiAvailable }: GraphDeps = defaultDeps) {
  const scan = (state: GraphState) => ({ signals: scanSignals(state.input) });

  /** Agent 1: the security analyst. */
  async function detect(state: GraphState) {
    try {
      const detection = await callAgent({
        system: DETECTOR_SYSTEM,
        user: detectorPrompt(state.input, state.signals),
        schema: DetectionSchema,
      });
      return { detection };
    } catch (err) {
      console.error("[phishguard] detector failed:", err);
      return { detection: null, aiError: describeModelError(err) };
    }
  }

  /** Agent 2: the educator. It words the report but cannot change the verdict. */
  async function explain(state: GraphState) {
    const detection = state.detection!;
    try {
      const explanation = await callAgent({
        system: EXPLAINER_SYSTEM,
        user: explainerPrompt(state.input, detection),
        schema: ExplanationSchema,
      });
      return { report: buildAiReport(detection, explanation) };
    } catch (err) {
      console.error("[phishguard] explainer failed:", err);
      return { report: buildAnalystReport(detection) };
    }
  }

  const patternReport = (state: GraphState) => ({
    report: buildPatternReport(state.signals, state.aiError),
  });

  return new StateGraph(State)
    .addNode("scan", scan)
    .addNode("detect", detect)
    .addNode("explain", explain)
    .addNode("pattern_report", patternReport)
    .addEdge(START, "scan")
    .addConditionalEdges("scan", () => (aiAvailable() ? "detect" : "pattern_report"), [
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
