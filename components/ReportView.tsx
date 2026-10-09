"use client";

import { useEffect, useRef, useState } from "react";
import type { Report } from "@/lib/phishguard/types";
import { AnnotatedMessage } from "./AnnotatedMessage";
import { ListCard } from "./ListCard";
import { RedFlagList } from "./RedFlagList";
import { MUTED } from "./styles";
import { VerdictBanner } from "./VerdictBanner";

type Props = { report: Report; message: string };

/** The full result for one checked message. */
export function ReportView({ report, message }: Props) {
  const sectionRef = useRef<HTMLElement>(null);
  const [activeFlag, setActiveFlag] = useState<number | null>(null);

  // Move focus to the result when it appears, so keyboard and screen-reader
  // users land on the verdict instead of staying on the submit button.
  useEffect(() => {
    const section = sectionRef.current;
    if (!section) return;
    section.focus({ preventScroll: true });
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    section.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
  }, []);

  return (
    <section
      ref={sectionRef}
      tabIndex={-1}
      aria-labelledby="result-heading"
      className="mt-8 scroll-mt-6 space-y-6 outline-none"
    >
      <VerdictBanner report={report} />

      {report.redFlags.length > 0 && (
        <section aria-labelledby="red-flags-heading">
          <h3 id="red-flags-heading" className="text-lg font-semibold">
            Why we think so
          </h3>
          <p className={`mt-1 text-sm ${MUTED}`}>
            The numbered highlights in your message match the warning signs below.
          </p>
          <AnnotatedMessage
            message={message}
            redFlags={report.redFlags}
            activeFlag={activeFlag}
            onActiveFlagChange={setActiveFlag}
          />
          <RedFlagList
            redFlags={report.redFlags}
            activeFlag={activeFlag}
            onActiveFlagChange={setActiveFlag}
          />
        </section>
      )}

      {report.reassuringSigns.length > 0 && (
        <ListCard title="What looks genuine" items={report.reassuringSigns} />
      )}
      <ListCard title="What to do now" items={report.safetySteps} ordered />
      {report.ifAlreadyClicked.length > 0 && (
        <ListCard
          title="If you already clicked, replied or paid"
          items={report.ifAlreadyClicked}
          ordered
        />
      )}

      <p className={`text-xs ${MUTED}`}>
        PhishGuard gives guidance, not a guarantee. When in doubt, contact the organisation through
        its official website or app.
      </p>
    </section>
  );
}
