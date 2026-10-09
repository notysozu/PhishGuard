import type {
  CheckOutcome,
  ReportVerdict,
  Severity,
  SiteClassification,
} from "@/lib/phishguard/types";

// Every state is conveyed by a text label as well as colour.

export const VERDICT_STYLE: Record<
  ReportVerdict,
  { label: string; banner: string; bar: string; text: string }
> = {
  dangerous: {
    label: "Likely a scam",
    banner: "bg-red-50 border-red-200 dark:bg-red-950/40 dark:border-red-900",
    bar: "bg-red-600",
    text: "text-red-700 dark:text-red-300",
  },
  suspicious: {
    label: "Be careful",
    banner: "bg-amber-50 border-amber-200 dark:bg-amber-950/40 dark:border-amber-900",
    bar: "bg-amber-600",
    text: "text-amber-800 dark:text-amber-300",
  },
  unverified: {
    label: "Not verified",
    banner: "bg-sky-50 border-sky-200 dark:bg-sky-950/40 dark:border-sky-900",
    bar: "bg-sky-600",
    text: "text-sky-800 dark:text-sky-300",
  },
  likely_safe: {
    label: "Looks okay",
    banner: "bg-emerald-50 border-emerald-200 dark:bg-emerald-950/40 dark:border-emerald-900",
    bar: "bg-emerald-600",
    text: "text-emerald-800 dark:text-emerald-300",
  },
};

export const SEVERITY_STYLE: Record<Severity, { label: string; badge: string; mark: string }> = {
  high: {
    label: "High risk",
    badge: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200",
    mark: "bg-red-100 decoration-red-500 dark:bg-red-900/50",
  },
  medium: {
    label: "Medium risk",
    badge: "bg-amber-100 text-amber-900 dark:bg-amber-950 dark:text-amber-200",
    mark: "bg-amber-100 decoration-amber-500 dark:bg-amber-900/50",
  },
  low: {
    label: "Low risk",
    badge: "bg-slate-200 text-slate-800 dark:bg-slate-800 dark:text-slate-200",
    mark: "bg-slate-200 decoration-slate-500 dark:bg-slate-700/70",
  },
};

const RED = "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200";
const AMBER = "bg-amber-100 text-amber-900 dark:bg-amber-950 dark:text-amber-200";
const SKY = "bg-sky-100 text-sky-900 dark:bg-sky-950 dark:text-sky-200";
const GREEN = "bg-emerald-100 text-emerald-900 dark:bg-emerald-950 dark:text-emerald-200";
const SLATE = "bg-slate-200 text-slate-800 dark:bg-slate-800 dark:text-slate-200";

export const SITE_STYLE: Record<SiteClassification, { label: string; badge: string; bar: string }> =
  {
    confirmed_malicious: { label: "Known dangerous", badge: RED, bar: "bg-red-600" },
    suspicious: { label: "Suspicious", badge: AMBER, bar: "bg-amber-600" },
    unverified: { label: "Unverified", badge: SKY, bar: "bg-sky-600" },
    no_known_issues: { label: "No known problems", badge: GREEN, bar: "bg-emerald-600" },
  };

export const OUTCOME_STYLE: Record<CheckOutcome, { label: string; badge: string }> = {
  good: { label: "Good sign", badge: GREEN },
  neutral: { label: "No concern", badge: SLATE },
  caution: { label: "Caution", badge: AMBER },
  bad: { label: "Warning", badge: RED },
  unavailable: {
    label: "Not checked",
    badge: "border border-dashed border-slate-400 text-slate-700 dark:text-slate-300",
  },
};

export const CARD =
  "rounded-2xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900";

export const MUTED = "text-slate-600 dark:text-slate-400";

/** DOM id of a red flag's explanation card; highlights in the message link to it. */
export const flagId = (index: number) => `warning-sign-${index + 1}`;
