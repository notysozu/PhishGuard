import type { Severity, Verdict } from "@/lib/phishguard/types";

// Every state is conveyed by a text label as well as colour.

export const VERDICT_STYLE: Record<
  Verdict,
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

export const CARD =
  "rounded-2xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900";

export const MUTED = "text-slate-600 dark:text-slate-400";

/** DOM id of a red flag's explanation card; highlights in the message link to it. */
export const flagId = (index: number) => `warning-sign-${index + 1}`;
