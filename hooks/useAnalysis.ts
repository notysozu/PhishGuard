"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { readNdjson } from "@/lib/phishguard/ndjson";
import type { ProgressStep, Report, StreamEvent } from "@/lib/phishguard/types";

type AnalysisState = {
  /** The workflow stage in progress, or null when idle. */
  step: ProgressStep | null;
  report: Report | null;
  error: string | null;
  /** The exact text the current report describes. */
  analysedText: string;
};

const IDLE: AnalysisState = { step: null, report: null, error: null, analysedText: "" };

const GENERIC_ERROR = "Something went wrong. Please try again.";

async function errorMessage(response: Response): Promise<string> {
  const body = await response.json().catch(() => null);
  return typeof body?.error === "string" ? body.error : GENERIC_ERROR;
}

/** Runs a message through POST /api/analyze and tracks progress and the result. */
export function useAnalysis() {
  const [state, setState] = useState<AnalysisState>(IDLE);
  const inFlight = useRef<AbortController | null>(null);

  // Cancel the request if the page goes away mid-check.
  useEffect(() => () => inFlight.current?.abort(), []);

  const analyse = useCallback(async (text: string) => {
    const input = text.trim();
    if (!input) return;

    inFlight.current?.abort();
    const controller = new AbortController();
    inFlight.current = controller;
    setState({ ...IDLE, step: "scan", analysedText: input });

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: input }),
        signal: controller.signal,
      });
      if (!response.ok || !response.body) throw new Error(await errorMessage(response));

      for await (const event of readNdjson<StreamEvent>(response.body)) {
        if (event.type === "step") setState((s) => ({ ...s, step: event.step }));
        else if (event.type === "error") setState((s) => ({ ...s, error: event.message }));
        else setState((s) => ({ ...s, report: event.report }));
      }
    } catch (err) {
      if (!controller.signal.aborted) {
        const message = err instanceof Error && err.message ? err.message : GENERIC_ERROR;
        setState((s) => ({ ...s, error: message }));
      }
    } finally {
      // A newer request may have replaced this one; only it may clear the step.
      if (inFlight.current === controller) {
        inFlight.current = null;
        setState((s) => ({ ...s, step: null }));
      }
    }
  }, []);

  return { ...state, busy: state.step !== null, analyse };
}
