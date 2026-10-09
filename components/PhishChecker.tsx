"use client";

import { useState } from "react";
import { useAnalysis } from "@/hooks/useAnalysis";
import { MessageForm } from "./MessageForm";
import { ProgressSteps } from "./ProgressSteps";
import { ReportView } from "./ReportView";

/** The interactive part of the page: input, progress, errors and the result. */
export function PhishChecker() {
  const [text, setText] = useState("");
  const { busy, step, report, error, analysedText, analyse } = useAnalysis();

  return (
    <>
      <MessageForm value={text} onChange={setText} onSubmit={() => analyse(text)} busy={busy} />

      {/* Always mounted so screen readers announce progress as it changes. */}
      <div role="status" aria-live="polite" className={step ? "mt-6" : undefined}>
        {step && <ProgressSteps current={step} />}
      </div>

      {error && (
        <p
          role="alert"
          className="mt-6 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-200"
        >
          {error}
        </p>
      )}

      {report && <ReportView report={report} message={analysedText} />}
    </>
  );
}
