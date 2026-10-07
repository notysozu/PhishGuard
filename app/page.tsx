"use client";

import { useMemo, useRef, useState } from "react";
import {
  MAX_INPUT_CHARS,
  type RedFlag,
  type Report,
  type StreamEvent,
  type Verdict,
} from "@/lib/phishguard/types";
import { SAMPLES } from "./samples";

type Step = "scan" | "detect" | "explain";

const STEPS: { id: Step; label: string }[] = [
  { id: "scan", label: "Scanning for known scam patterns" },
  { id: "detect", label: "Security analyst reviewing the message" },
  { id: "explain", label: "Writing your plain-language explanation" },
];

const VERDICT: Record<
  Verdict,
  { label: string; banner: string; bar: string; text: string }
> = {
  dangerous: {
    label: "Likely a scam",
    banner: "bg-red-50 border-red-200 dark:bg-red-950/40 dark:border-red-900",
    bar: "bg-red-500",
    text: "text-red-700 dark:text-red-300",
  },
  suspicious: {
    label: "Be careful",
    banner: "bg-amber-50 border-amber-200 dark:bg-amber-950/40 dark:border-amber-900",
    bar: "bg-amber-500",
    text: "text-amber-700 dark:text-amber-300",
  },
  likely_safe: {
    label: "Looks okay",
    banner: "bg-emerald-50 border-emerald-200 dark:bg-emerald-950/40 dark:border-emerald-900",
    bar: "bg-emerald-500",
    text: "text-emerald-700 dark:text-emerald-300",
  },
};

const SEVERITY_DOT = {
  high: "bg-red-500",
  medium: "bg-amber-500",
  low: "bg-slate-400",
};

const MARK = {
  high: "bg-red-100 decoration-red-400 dark:bg-red-900/50",
  medium: "bg-amber-100 decoration-amber-400 dark:bg-amber-900/50",
  low: "bg-slate-200 decoration-slate-400 dark:bg-slate-700/70",
};

type Segment = { text: string; flag?: number };

/** Split the original message into plain and highlighted runs. */
function segment(text: string, flags: RedFlag[]): Segment[] {
  const lower = text.toLowerCase();
  const ranges: { start: number; end: number; flag: number }[] = [];
  flags.forEach((f, flag) => {
    const needle = f.evidence.trim();
    if (!needle) return;
    let start = text.indexOf(needle);
    if (start < 0) start = lower.indexOf(needle.toLowerCase());
    if (start < 0) return;
    const end = start + needle.length;
    if (ranges.some((r) => start < r.end && end > r.start)) return;
    ranges.push({ start, end, flag });
  });
  ranges.sort((a, b) => a.start - b.start);

  const out: Segment[] = [];
  let pos = 0;
  for (const r of ranges) {
    if (r.start > pos) out.push({ text: text.slice(pos, r.start) });
    out.push({ text: text.slice(r.start, r.end), flag: r.flag });
    pos = r.end;
  }
  if (pos < text.length) out.push({ text: text.slice(pos) });
  return out;
}

export default function Home() {
  const [text, setText] = useState("");
  const [analysed, setAnalysed] = useState("");
  const [step, setStep] = useState<Step | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [active, setActive] = useState<number | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);

  const busy = step !== null;

  async function analyse() {
    const input = text.trim();
    if (!input || busy) return;
    setReport(null);
    setError(null);
    setActive(null);
    setAnalysed(input);
    setStep("scan");
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: input }),
      });
      if (!res.ok || !res.body) {
        const body = await res.json().catch(() => null);
        throw new Error(body?.error ?? "Something went wrong. Please try again.");
      }
      const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
      let buffer = "";
      let done = false;
      while (!done) {
        const chunk = await reader.read();
        done = chunk.done;
        buffer += chunk.value ?? "";
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          if (!line) continue;
          const event = JSON.parse(line) as StreamEvent;
          if (event.type === "step") setStep(event.step);
          else if (event.type === "error") setError(event.message);
          else {
            setReport(event.report);
            requestAnimationFrame(() =>
              resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })
            );
          }
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setStep(null);
    }
  }

  const segments = useMemo(
    () => (report ? segment(analysed, report.redFlags) : []),
    [report, analysed]
  );
  const v = report ? VERDICT[report.verdict] : null;

  return (
    <main className="mx-auto w-full max-w-3xl px-4 py-10 sm:py-16">
      <header className="mb-8">
        <p className="flex items-center gap-2 text-sm font-semibold tracking-wide text-teal-700 dark:text-teal-400">
          <ShieldIcon /> PhishGuard
        </p>
        <h1 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">
          Not sure about a message? Check it before you click.
        </h1>
        <p className="mt-3 text-base text-slate-600 dark:text-slate-400">
          Paste a suspicious email, text or link. We&apos;ll tell you whether it
          looks like a scam, show you exactly why, and what to do next.
        </p>
      </header>

      <section className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:p-5 dark:border-slate-800 dark:bg-slate-900">
        <label htmlFor="message" className="sr-only">
          Message to check
        </label>
        <textarea
          id="message"
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) analyse();
          }}
          maxLength={MAX_INPUT_CHARS}
          rows={8}
          placeholder="Paste the email, text message or link here…"
          className="w-full resize-y rounded-lg border border-slate-200 bg-slate-50 p-3 font-mono text-sm leading-relaxed outline-none placeholder:font-sans placeholder:text-slate-400 focus:border-teal-500 focus:ring-2 focus:ring-teal-500/20 dark:border-slate-700 dark:bg-slate-950"
        />
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <span className="text-sm text-slate-500">Try an example:</span>
          {SAMPLES.map((s) => (
            <button
              key={s.label}
              type="button"
              onClick={() => setText(s.text)}
              className="rounded-full border border-slate-200 px-3 py-1 text-sm text-slate-700 hover:border-teal-500 hover:text-teal-700 dark:border-slate-700 dark:text-slate-300 dark:hover:text-teal-400"
            >
              {s.label}
            </button>
          ))}
        </div>
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs text-slate-500">
            We never open links in your message, and nothing you paste is stored.
          </p>
          <button
            type="button"
            onClick={analyse}
            disabled={busy || !text.trim()}
            className="rounded-lg bg-teal-700 px-5 py-2.5 text-sm font-semibold text-white hover:bg-teal-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? "Checking…" : "Check this message"}
          </button>
        </div>
      </section>

      {busy && (
        <ol className="mt-6 space-y-2" aria-live="polite">
          {STEPS.map((s, i) => {
            const current = STEPS.findIndex((x) => x.id === step);
            const state = i < current ? "done" : i === current ? "now" : "todo";
            return (
              <li
                key={s.id}
                className={`flex items-center gap-3 text-sm ${
                  state === "todo" ? "text-slate-400" : ""
                }`}
              >
                <span
                  className={`h-2.5 w-2.5 rounded-full ${
                    state === "done"
                      ? "bg-teal-600"
                      : state === "now"
                        ? "animate-pulse bg-teal-500"
                        : "bg-slate-300 dark:bg-slate-700"
                  }`}
                />
                {s.label}
              </li>
            );
          })}
        </ol>
      )}

      {error && (
        <p role="alert" className="mt-6 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-200">
          {error}
        </p>
      )}

      {report && v && (
        <div ref={resultRef} className="mt-8 scroll-mt-6 space-y-6">
          <section className={`rounded-2xl border p-5 ${v.banner}`}>
            <div className="flex items-baseline justify-between gap-4">
              <p className={`text-sm font-semibold uppercase tracking-wide ${v.text}`}>
                {v.label}
              </p>
              <p className="text-sm tabular-nums text-slate-600 dark:text-slate-400">
                Risk {report.riskScore}/100
              </p>
            </div>
            <div
              className="mt-2 h-1.5 overflow-hidden rounded-full bg-black/10 dark:bg-white/10"
              role="meter"
              aria-label="Risk score"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={report.riskScore}
            >
              <div className={`h-full ${v.bar}`} style={{ width: `${report.riskScore}%` }} />
            </div>
            <h2 className="mt-4 text-xl font-semibold">{report.headline}</h2>
            <p className="mt-2 text-slate-700 dark:text-slate-300">{report.summary}</p>
            {report.notice && (
              <p className="mt-3 text-xs text-slate-600 dark:text-slate-400">{report.notice}</p>
            )}
          </section>

          {report.redFlags.length > 0 && (
            <section>
              <h3 className="text-lg font-semibold">Why we think so</h3>
              <p className="mt-1 text-sm text-slate-500">
                The numbered highlights in your message match the warning signs below.
              </p>
              <pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-xl border border-slate-200 bg-white p-4 font-mono text-sm leading-7 dark:border-slate-800 dark:bg-slate-900">
                {segments.map((s, i) =>
                  s.flag === undefined ? (
                    <span key={i}>{s.text}</span>
                  ) : (
                    <mark
                      key={i}
                      onMouseEnter={() => setActive(s.flag!)}
                      onMouseLeave={() => setActive(null)}
                      className={`rounded px-0.5 text-inherit underline decoration-2 underline-offset-4 ${
                        MARK[report.redFlags[s.flag].severity]
                      } ${active === s.flag ? "ring-2 ring-teal-500" : ""}`}
                    >
                      {s.text}
                      <sup className="ml-0.5 font-sans text-[10px] font-bold">{s.flag + 1}</sup>
                    </mark>
                  )
                )}
              </pre>
              <ol className="mt-4 space-y-3">
                {report.redFlags.map((f, i) => (
                  <li
                    key={i}
                    onMouseEnter={() => setActive(i)}
                    onMouseLeave={() => setActive(null)}
                    className={`rounded-xl border bg-white p-4 dark:bg-slate-900 ${
                      active === i
                        ? "border-teal-500"
                        : "border-slate-200 dark:border-slate-800"
                    }`}
                  >
                    <p className="flex items-center gap-2 font-semibold">
                      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-900 text-[11px] text-white dark:bg-slate-100 dark:text-slate-900">
                        {i + 1}
                      </span>
                      {f.title}
                      <span
                        className={`ml-auto h-2 w-2 shrink-0 rounded-full ${SEVERITY_DOT[f.severity]}`}
                        title={`${f.severity} severity`}
                      />
                    </p>
                    {f.evidence && (
                      <p className="mt-2 break-all border-l-2 border-slate-300 pl-3 font-mono text-xs text-slate-600 dark:border-slate-700 dark:text-slate-400">
                        {f.evidence}
                      </p>
                    )}
                    <p className="mt-2 text-sm text-slate-700 dark:text-slate-300">
                      {f.explanation}
                    </p>
                  </li>
                ))}
              </ol>
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

          <p className="text-xs text-slate-500">
            PhishGuard gives guidance, not a guarantee. When in doubt, contact the
            organisation through its official website or app.
          </p>
        </div>
      )}
    </main>
  );
}

function ListCard({
  title,
  items,
  ordered,
}: {
  title: string;
  items: string[];
  ordered?: boolean;
}) {
  const List = ordered ? "ol" : "ul";
  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
      <h3 className="text-lg font-semibold">{title}</h3>
      <List
        className={`mt-3 space-y-2 pl-5 text-slate-700 dark:text-slate-300 ${
          ordered ? "list-decimal" : "list-disc"
        }`}
      >
        {items.map((item, i) => (
          <li key={i}>{item}</li>
        ))}
      </List>
    </section>
  );
}

function ShieldIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M12 3l8 3v6c0 4.5-3.2 8.3-8 9-4.8-.7-8-4.5-8-9V6l8-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}
