import net from "node:net";
import { extractUrls, parseHost, registrableDomain } from "../signals";
import type { Signal, SiteReport } from "../types";
import {
  lookupRegistration,
  lookupSafeBrowsing,
  lookupTrustpilot,
  lookupVirusTotal,
  type Lookup,
} from "./intel";
import { checkLottery } from "./lotteries";
import { traceRedirects, type RedirectTrace } from "./redirects";
import { assessSite } from "./trust";

/** Set PHISHGUARD_SITE_CHECKS=off to make no outbound requests about pasted links. */
export const siteChecksEnabled = () => process.env.PHISHGUARD_SITE_CHECKS !== "off";

/** The outside world, as the verifier sees it. Swappable in tests. */
export type SiteDeps = {
  traceRedirects: (url: string) => Promise<RedirectTrace>;
  lookupRegistration: typeof lookupRegistration;
  lookupTrustpilot: typeof lookupTrustpilot;
  lookupSafeBrowsing: typeof lookupSafeBrowsing;
  lookupVirusTotal: typeof lookupVirusTotal;
  now: () => Date;
};

const TRACE_BUDGET_MS = 10_000;

const defaultDeps: SiteDeps = {
  traceRedirects: (url) => traceRedirects(url),
  lookupRegistration: (domain) => lookupRegistration(domain),
  lookupTrustpilot: (domain) => lookupTrustpilot(domain),
  lookupSafeBrowsing: (urls) => lookupSafeBrowsing(urls),
  lookupVirusTotal: (domain) => lookupVirusTotal(domain),
  now: () => new Date(),
};

/**
 * The one link worth verifying: the one the scanner found most suspicious,
 * otherwise the first. Null when the text has no link.
 */
export function pickUrl(text: string, signals: Signal[]): string | null {
  const urls = extractUrls(text);
  if (urls.length === 0) return null;
  const rank = { high: 2, medium: 1, low: 0 };
  const flagged = signals
    .filter((signal) => signal.category === "suspicious_link")
    .sort((a, b) => rank[b.severity] - rank[a.severity]);
  for (const signal of flagged) {
    const match = urls.find((url) => signal.evidence.includes(url));
    if (match) return match;
  }
  return urls[0];
}

/** The address without its query string, so personal tokens are not sent to third parties. */
function withoutQuery(address: string): string {
  const url = new URL(address);
  url.search = "";
  url.hash = "";
  return url.href;
}

async function traceWithin(deps: SiteDeps, url: string): Promise<RedirectTrace> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<RedirectTrace>((resolve) => {
    timer = setTimeout(
      () =>
        resolve({
          followed: false,
          chain: [url],
          finalUrl: url,
          note: "Following the link took too long.",
        }),
      TRACE_BUDGET_MS,
    );
  });
  try {
    return await Promise.race([deps.traceRedirects(url), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

const NO_DOMAIN_RECORD: Lookup<never> = {
  state: "error",
  reason: "A raw IP address has no domain record to look up.",
};

/**
 * Verifies the main link in `text`: where it leads, how old the domain is,
 * whether it is on a threat list, its reputation, and (for lotteries) whether
 * it belongs to the official organizer. Returns null when there is no link.
 */
export async function verifySite(
  text: string,
  signals: Signal[],
  deps: SiteDeps = defaultDeps,
): Promise<SiteReport | null> {
  const raw = pickUrl(text, signals);
  if (!raw) return null;

  const hasScheme = /^https?:\/\//i.test(raw);
  let url = hasScheme ? raw : `https://${raw}`;
  if (!URL.canParse(url) || !parseHost(url)) return null;

  let trace = await traceWithin(deps, url);
  let schemeAssumed = false;
  if (!hasScheme && !trace.followed) {
    // No scheme was given and https did not answer: the site may be http only.
    const plain = `http://${raw}`;
    const retry = await traceWithin(deps, plain);
    if (retry.followed) [url, trace] = [plain, retry];
    else schemeAssumed = true;
  }

  const finalHost = parseHost(trace.finalUrl) ?? parseHost(url)!;
  const domain = registrableDomain(finalHost);
  const isIp = net.isIP(finalHost) !== 0;
  const addresses = [...new Set([url, trace.finalUrl].map(withoutQuery))];

  const [registration, trustpilot, safeBrowsing, virusTotal] = await Promise.all([
    isIp ? NO_DOMAIN_RECORD : deps.lookupRegistration(domain),
    isIp ? NO_DOMAIN_RECORD : deps.lookupTrustpilot(domain),
    deps.lookupSafeBrowsing(addresses),
    isIp ? NO_DOMAIN_RECORD : deps.lookupVirusTotal(domain),
  ]);

  return assessSite({
    url,
    schemeAssumed,
    trace,
    registration,
    trustpilot,
    safeBrowsing,
    virusTotal,
    lottery: checkLottery(text, trace.finalUrl, domain),
    signals,
    now: deps.now(),
  });
}
