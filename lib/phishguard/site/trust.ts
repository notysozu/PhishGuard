import net from "node:net";
import {
  KNOWN_BRAND_COUNT,
  impersonatedBrand,
  isShortener,
  ownBrandDomain,
  parseHost,
  registrableDomain,
} from "../signals";
import type {
  CheckOutcome,
  Signal,
  SiteCheck,
  SiteCheckId,
  SiteClassification,
  SiteReport,
} from "../types";
import type {
  Lookup,
  Registration,
  SafeBrowsingResult,
  TrustpilotProfile,
  VirusTotalResult,
} from "./intel";
import { KNOWN_LOTTERY_COUNT, type LotteryResult } from "./lotteries";
import type { RedirectTrace } from "./redirects";

// Turns raw lookups into an explained trust score. Pure: no network, no clock.
//
// The score starts at 50 ("we know nothing") and each check moves it by a
// stated number of points. Missing information never moves it: a lookup that
// failed is reported as "not checked", not as a warning sign.

/** Everything gathered about one link. */
export type SiteFacts = {
  /** The link as checked. Always has a scheme. */
  url: string;
  /** True when the user typed no scheme and https could not be confirmed. */
  schemeAssumed: boolean;
  trace: RedirectTrace;
  registration: Lookup<Registration>;
  trustpilot: Lookup<TrustpilotProfile>;
  safeBrowsing: Lookup<SafeBrowsingResult>;
  virusTotal: Lookup<VirusTotalResult>;
  lottery: LotteryResult;
  /** Scanner findings from the message the link came in. */
  signals: Signal[];
  now: Date;
};

const BASE_SCORE = 50;
const DAY_MS = 86_400_000;

/** What a check contributes to the overall classification, beyond its points. */
type Weight = "malicious" | "suspicious" | "corroborates";
type Assessed = {
  check: SiteCheck;
  weight?: Weight;
  /** How much independent confirmation this is worth. Defaults to 1 for "corroborates". */
  corroborations?: number;
  /** True when something essential could not be confirmed, so the site cannot be rated clean. */
  unconfirmed?: boolean;
};

const formatDate = (date: Date) =>
  new Intl.DateTimeFormat("en-GB", {
    day: "numeric",
    month: "long",
    year: "numeric",
    timeZone: "UTC",
  }).format(date);

function formatAge(days: number): string {
  if (days < 60) return `${days} day${days === 1 ? "" : "s"} ago`;
  if (days < 730) return `${Math.floor(days / 30)} months ago`;
  return `${Math.floor(days / 365)} years ago`;
}

const check = (
  id: SiteCheckId,
  label: string,
  outcome: CheckOutcome,
  impact: number,
  summary: string,
  evidence: string,
  source?: SiteCheck["source"],
): SiteCheck => ({ id, label, outcome, summary, evidence, impact, source });

/** A check that could not run. It never changes the score. */
function notChecked(
  id: SiteCheckId,
  label: string,
  service: string,
  lookup: { state: "not_configured" } | { state: "error"; reason: string },
  source?: SiteCheck["source"],
): Assessed {
  const why =
    lookup.state === "not_configured"
      ? `This PhishGuard server has no ${service} API key, so this check was skipped.`
      : `${lookup.reason} This check was skipped.`;
  return {
    check: check(
      id,
      label,
      "unavailable",
      0,
      "Not checked",
      `${why} That says nothing about the website either way.`,
      source,
    ),
  };
}

const THREAT_NAMES: Record<string, string> = {
  SOCIAL_ENGINEERING: "phishing",
  MALWARE: "malware",
  UNWANTED_SOFTWARE: "unwanted software",
  POTENTIALLY_HARMFUL_APPLICATION: "harmful apps",
};

function safeBrowsingCheck({ safeBrowsing, now }: SiteFacts, domain: string): Assessed {
  const label = "Google Safe Browsing";
  const source = {
    name: "Google Transparency Report",
    url: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(domain)}`,
  };
  if (safeBrowsing.state !== "found") {
    const lookup =
      safeBrowsing.state === "not_found"
        ? { state: "error" as const, reason: "No answer was returned." }
        : safeBrowsing;
    return notChecked("safe_browsing", label, "Google Safe Browsing", lookup, source);
  }
  const { threats } = safeBrowsing.data;
  if (threats.length > 0) {
    const names = threats.map((threat) => THREAT_NAMES[threat] ?? threat.toLowerCase()).join(", ");
    return {
      weight: "malicious",
      check: check(
        "safe_browsing",
        label,
        "bad",
        -60,
        `Listed by Google as unsafe (${names})`,
        `Google Safe Browsing lists this address for: ${names}. Checked on ${formatDate(now)}.`,
        source,
      ),
    };
  }
  return {
    weight: "corroborates",
    check: check(
      "safe_browsing",
      label,
      "good",
      5,
      "Not on Google's list of unsafe websites",
      `Checked on ${formatDate(now)}. New scam sites can take days to be listed, so this is not proof of safety.`,
      source,
    ),
  };
}

function virusTotalCheck({ virusTotal }: SiteFacts, domain: string): Assessed {
  const label = "VirusTotal";
  const source = {
    name: "VirusTotal",
    url: `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`,
  };
  if (virusTotal.state === "not_configured" || virusTotal.state === "error") {
    return notChecked("virustotal", label, "VirusTotal", virusTotal, source);
  }
  if (virusTotal.state === "not_found") {
    return {
      check: check(
        "virustotal",
        label,
        "neutral",
        0,
        "No record yet",
        "No security vendor has analysed this domain. That is common for new or small websites and is not a warning sign by itself.",
        source,
      ),
    };
  }
  const { malicious, suspicious, total } = virusTotal.data;
  const counts = `${malicious} of ${total} security vendors flag this domain as malicious and ${suspicious} as suspicious.`;
  if (malicious >= 3) {
    return {
      weight: "malicious",
      check: check(
        "virustotal",
        label,
        "bad",
        -60,
        "Flagged as malicious by several security vendors",
        counts,
        source,
      ),
    };
  }
  if (malicious > 0 || suspicious >= 2) {
    return {
      weight: "suspicious",
      check: check(
        "virustotal",
        label,
        "caution",
        -20,
        "Flagged by a small number of security vendors",
        `${counts} A single flag can be a false alarm, so treat this as a caution rather than proof.`,
        source,
      ),
    };
  }
  return {
    weight: "corroborates",
    check: check(
      "virustotal",
      label,
      "good",
      10,
      "No security vendor flags this domain",
      counts,
      source,
    ),
  };
}

function impersonationCheck(hosts: string[], url: string): Assessed {
  const label = "Look-alike and impersonation";
  const problems: string[] = [];
  for (const host of hosts) {
    const brand = impersonatedBrand(host);
    if (brand)
      problems.push(
        `"${host}" uses the name "${brand}" but belongs to ${registrableDomain(host)}, not to ${brand}.`,
      );
    if (host.includes("xn--"))
      problems.push(`"${host}" uses international look-alike characters (punycode).`);
    if (net.isIPv4(host))
      problems.push(`"${host}" is a raw IP address instead of a named website.`);
  }
  if (/^https?:\/\/[^/]*@/i.test(url))
    problems.push('The address contains "@", which hides the real destination.');

  if (problems.length > 0) {
    return {
      weight: "suspicious",
      check: check(
        "impersonation",
        label,
        "bad",
        -30,
        "The address imitates a trusted name or hides its destination",
        [...new Set(problems)].join(" "),
      ),
    };
  }
  const brand = ownBrandDomain(hosts[hosts.length - 1]);
  if (brand) {
    return {
      weight: "corroborates",
      check: check(
        "impersonation",
        label,
        "good",
        10,
        `This is ${brand}'s own domain`,
        `${registrableDomain(hosts[hosts.length - 1])} is the registered domain of a well-known brand, not a look-alike.`,
      ),
    };
  }
  return {
    check: check(
      "impersonation",
      label,
      "neutral",
      0,
      "Does not imitate a well-known brand",
      `Compared against ${KNOWN_BRAND_COUNT} commonly impersonated brands. No look-alike spelling, hidden destination or raw IP address was found.`,
    ),
  };
}

function redirectsCheck({ url, trace }: SiteFacts): Assessed {
  const label = "Redirects";
  if (!trace.followed) {
    return {
      unconfirmed: true,
      check: check(
        "redirects",
        label,
        "unavailable",
        0,
        "Could not follow the link",
        `${trace.note ?? "The link could not be opened."} That says nothing about the website either way.`,
      ),
    };
  }
  const startHost = parseHost(url) ?? "";
  const finalHost = parseHost(trace.finalUrl) ?? "";
  const hops = trace.chain.length - 1;
  const note = trace.note ? ` ${trace.note}` : "";

  if (hops === 0 && isShortener(startHost)) {
    return {
      unconfirmed: true,
      check: check(
        "redirects",
        label,
        "caution",
        -5,
        "Shortened link that does not reveal its destination",
        `${startHost} is a link shortener, but this link did not redirect anywhere. It may have been removed, or it may only work in a browser. The checks below describe the shortener, not the real destination.`,
      ),
    };
  }
  if (hops === 0) {
    return {
      check: check(
        "redirects",
        label,
        "neutral",
        0,
        "No redirects",
        `The link opens ${finalHost} directly.${note}`,
      ),
    };
  }
  const path = trace.chain.map((step) => parseHost(step) ?? step).join(" → ");
  const followedText = `Followed ${hops} redirect${hops === 1 ? "" : "s"}: ${path}.`;
  const sameSite = registrableDomain(startHost) === registrableDomain(finalHost);
  if (sameSite && hops <= 3 && !trace.note) {
    return {
      check: check("redirects", label, "neutral", 0, "Stays on the same website", followedText),
    };
  }
  const impact = (sameSite ? 0 : -5) + (hops > 3 || trace.note ? -5 : 0);
  const summary = sameSite
    ? "Unusually long redirect chain"
    : isShortener(startHost)
      ? `Shortened link that leads to ${finalHost}`
      : `Redirects to a different website: ${finalHost}`;
  return {
    check: check(
      "redirects",
      label,
      "caution",
      impact,
      summary,
      `${followedText}${note} The remaining checks describe the final destination.`,
    ),
  };
}

function domainAgeCheck(
  { registration, now }: SiteFacts,
  domain: string,
): Assessed & { ageDays: number | null } {
  const label = "Domain age and ownership";
  const source = {
    name: "ICANN registration lookup",
    url: `https://lookup.icann.org/en/lookup?name=${encodeURIComponent(domain)}`,
  };
  if (registration.state === "not_configured" || registration.state === "error") {
    return {
      ...notChecked("domain_age", label, "registration", registration, source),
      ageDays: null,
    };
  }
  if (registration.state === "not_found") {
    return {
      ageDays: null,
      unconfirmed: true,
      check: check(
        "domain_age",
        label,
        "unavailable",
        0,
        "No registration record found",
        `The registry has no record of ${domain}. The website may not exist, or the address may be mistyped.`,
        source,
      ),
    };
  }
  if (!registration.data.registeredAt) {
    return {
      ageDays: null,
      check: check(
        "domain_age",
        label,
        "unavailable",
        0,
        "No registration date available",
        `The registry published no registration date for ${domain}. That says nothing about the website either way.`,
        source,
      ),
    };
  }
  const { registeredAt, registrar, registrant } = registration.data;
  const registered = new Date(registeredAt);
  const ageDays = Math.max(0, Math.floor((now.getTime() - registered.getTime()) / DAY_MS));
  const owner = registrant
    ? `Registered to ${registrant}.`
    : "The owner's details are not public, which is normal for most domains.";
  const evidence = `${domain} was registered on ${formatDate(registered)} (${formatAge(ageDays)})${
    registrar ? ` through ${registrar}` : ""
  }. ${owner}`;

  if (ageDays < 30) {
    return {
      ageDays,
      check: check(
        "domain_age",
        label,
        "bad",
        -25,
        `Created only ${formatAge(ageDays)}`,
        `${evidence} Scam sites are usually days or weeks old, though new honest sites exist too.`,
        source,
      ),
    };
  }
  if (ageDays < 180) {
    return {
      ageDays,
      check: check(
        "domain_age",
        label,
        "caution",
        -10,
        `Fairly new: registered ${formatAge(ageDays)}`,
        evidence,
        source,
      ),
    };
  }
  if (ageDays < 365) {
    return {
      ageDays,
      check: check(
        "domain_age",
        label,
        "neutral",
        0,
        `Registered ${formatAge(ageDays)}`,
        evidence,
        source,
      ),
    };
  }
  const longEstablished = ageDays >= 5 * 365;
  return {
    ageDays,
    weight: "corroborates",
    corroborations: longEstablished ? 2 : 1,
    check: check(
      "domain_age",
      label,
      "good",
      longEstablished ? 15 : 10,
      `Established: registered ${formatAge(ageDays)}`,
      `${evidence} Age alone does not prove a site is honest.`,
      source,
    ),
  };
}

function httpsCheck({ url, schemeAssumed, trace }: SiteFacts): Assessed {
  const label = "Secure connection (HTTPS)";
  const address = trace.followed ? trace.finalUrl : url;
  if (address.startsWith("http://") && !schemeAssumed) {
    return {
      check: check(
        "https",
        label,
        "caution",
        -10,
        "Not encrypted",
        "The address starts with http, so anything typed into it could be read in transit. Legitimate shops and lotteries use https.",
      ),
    };
  }
  if (!trace.followed) {
    return {
      check: check(
        "https",
        label,
        "unavailable",
        0,
        "Could not confirm",
        "The website did not respond, so its connection could not be checked.",
      ),
    };
  }
  return {
    check: check(
      "https",
      label,
      "good",
      5,
      "Uses an encrypted connection",
      "The address starts with https. This protects data in transit only: scam sites use https too.",
    ),
  };
}

function trustpilotCheck({ trustpilot }: SiteFacts, domain: string): Assessed {
  const label = "Trustpilot reputation";
  const search = {
    name: "Search Trustpilot",
    url: `https://www.trustpilot.com/search?query=${encodeURIComponent(domain)}`,
  };
  const caveat = "A good rating does not guarantee a website is legitimate.";
  if (trustpilot.state === "not_configured" || trustpilot.state === "error") {
    return notChecked("trustpilot", label, "Trustpilot", trustpilot, search);
  }
  if (trustpilot.state === "not_found") {
    return {
      check: check(
        "trustpilot",
        label,
        "neutral",
        0,
        "No Trustpilot profile for this exact domain",
        "Many legitimate websites have no profile, so this is not a warning sign by itself. Profiles of similarly named businesses were ignored.",
        search,
      ),
    };
  }
  const { name, identifyingName, trustScore, reviews, profileUrl } = trustpilot.data;
  const source = { name: "Trustpilot profile", url: profileUrl };
  const rating = `Rated ${trustScore.toFixed(1)} out of 5 from ${reviews.toLocaleString("en")} review${reviews === 1 ? "" : "s"}`;
  const evidence = `Trustpilot profile "${name}", filed under ${identifyingName}. ${caveat}`;
  if (reviews < 25) {
    return {
      check: check(
        "trustpilot",
        label,
        "neutral",
        0,
        `${rating} (too few to rely on)`,
        evidence,
        source,
      ),
    };
  }
  if (trustScore < 2.5) {
    return {
      check: check(
        "trustpilot",
        label,
        "caution",
        -15,
        `${rating}: mostly negative`,
        `${evidence} Read the recent reviews before buying or paying.`,
        source,
      ),
    };
  }
  if (trustScore >= 4) {
    return {
      weight: "corroborates",
      check: check("trustpilot", label, "good", 10, rating, evidence, source),
    };
  }
  return {
    weight: "corroborates",
    check: check("trustpilot", label, "neutral", 0, `${rating}: mixed`, evidence, source),
  };
}

const NEVER_PAY =
  "Real lotteries publish winners and terms on their own official website, and never ask winners to pay a fee or share a code.";

function lotteryCheck({ lottery }: SiteFacts, domain: string): Assessed | null {
  const label = "Lottery organizer";
  switch (lottery.kind) {
    case "not_lottery":
      return null;
    case "official":
      return {
        weight: "corroborates",
        corroborations: 2,
        check: check(
          "lottery",
          label,
          "good",
          20,
          `Official website of ${lottery.lottery.name}`,
          `${domain} is a website of ${lottery.lottery.organizer}. If a message says you won, still check the draw result there yourself.`,
          { name: "Official results", url: lottery.lottery.verifyUrl },
        ),
      };
    case "impersonation":
      return {
        weight: "suspicious",
        check: check(
          "lottery",
          label,
          "bad",
          -30,
          `Claims to be ${lottery.lottery.name}, but is not its official website`,
          `${lottery.lottery.name} is run by ${lottery.lottery.organizer} and publishes results only on ${lottery.lottery.officialDomains[0]}. ${domain} is not one of its websites. ${NEVER_PAY}`,
          { name: "Official results", url: lottery.lottery.verifyUrl },
        ),
      };
    case "scam_theme":
      return {
        weight: "suspicious",
        check: check(
          "lottery",
          label,
          "bad",
          -30,
          `"${lottery.name}" is a well-known scam theme`,
          `Messages about a "${lottery.name}" have circulated for years, and the named company runs no such draw. ${NEVER_PAY}`,
        ),
      };
    case "unknown_organizer": {
      const hint = lottery.lottery
        ? ` ${lottery.lottery.name} is mentioned: its results are published only on ${lottery.lottery.officialDomains[0]}.`
        : "";
      return {
        unconfirmed: true,
        check: check(
          "lottery",
          label,
          "caution",
          -5,
          "No reliable confirmation of the lottery organizer was found",
          `${domain} is not among the ${KNOWN_LOTTERY_COUNT} official lottery organizers PhishGuard can confirm. That does not make it fake, but it could not be verified.${hint} ${NEVER_PAY}`,
          lottery.lottery && { name: "Official results", url: lottery.lottery.verifyUrl },
        ),
      };
    }
  }
}

function paymentCheck({ signals }: SiteFacts, prizeContext: boolean): Assessed | null {
  const label = "Requests for money or codes";
  const asks = signals.filter(
    (signal) => signal.category === "payment_request" || signal.category === "credential_request",
  );
  const quotes = [...new Set(asks.map((signal) => `"${signal.evidence}"`))].join(", ");
  if (prizeContext && asks.length > 0) {
    return {
      weight: "suspicious",
      check: check(
        "payment",
        label,
        "bad",
        -20,
        "Asks for a fee, tax or code before you can claim a prize",
        `The message says: ${quotes}. Genuine lotteries take any tax out of the prize. They never ask winners to pay first or to share a one-time code.`,
      ),
    };
  }
  if (asks.some((signal) => signal.category === "payment_request")) {
    return {
      check: check(
        "payment",
        label,
        "caution",
        -10,
        "Asks for payment in the message",
        `The message says: ${quotes}. Be careful with fees you did not expect, and with payment methods that cannot be reversed.`,
      ),
    };
  }
  return null;
}

type Wording = Pick<SiteReport, "headline" | "summary" | "recommendedAction">;

function wording(classification: SiteClassification, aboutLottery: boolean): Wording {
  switch (classification) {
    case "confirmed_malicious":
      return {
        headline: "Known dangerous website",
        summary: "This website is on a security threat list.",
        recommendedAction:
          "Do not open it or enter any details. If you already did, change the passwords you typed and contact your bank.",
      };
    case "suspicious":
      return {
        headline: "Suspicious website",
        summary: "This website shows concrete warning signs, though it is not on a threat list.",
        recommendedAction:
          "Don't enter personal details or pay anything here. Reach the organisation by typing its official address yourself.",
      };
    case "unverified":
      return aboutLottery
        ? {
            headline: "Unverified website",
            summary: "No reliable confirmation of the lottery organizer was found.",
            recommendedAction:
              "Verify the announcement on the organizer's official website before providing personal details or paying any fees.",
          }
        : {
            headline: "Unverified website",
            summary:
              "We found no known threats, but could not confirm who runs this website. That does not make it a scam.",
            recommendedAction:
              "Be cautious with personal or payment details until you have confirmed the business another way.",
          };
    case "no_known_issues":
      return {
        headline: "No known problems found",
        summary:
          "Nothing we checked raised a concern, and what we could confirm is consistent with an established website.",
        recommendedAction:
          "Still make sure the address is exactly right before you sign in or pay.",
      };
  }
}

const SCORE_CAPS: Partial<Record<SiteClassification, { max: number; why: string }>> = {
  confirmed_malicious: { max: 10, why: "the website is on a threat list" },
  suspicious: { max: 45, why: "the website shows warning signs" },
  unverified: { max: 65, why: "nothing confirms who runs the website" },
};

/** Scores and classifies a website from everything gathered about it. */
export function assessSite(facts: SiteFacts): SiteReport {
  const startHost = parseHost(facts.url) ?? "";
  const finalHost = parseHost(facts.trace.finalUrl) ?? startHost;
  const domain = registrableDomain(finalHost);
  const hosts = [...new Set([startHost, finalHost])];

  const aboutLottery = facts.lottery.kind !== "not_lottery";
  const prizeContext =
    aboutLottery || facts.signals.some((signal) => signal.category === "too_good_to_be_true");

  const age = domainAgeCheck(facts, domain);
  const assessed = [
    safeBrowsingCheck(facts, domain),
    virusTotalCheck(facts, domain),
    impersonationCheck(hosts, facts.url),
    redirectsCheck(facts),
    age,
    httpsCheck(facts),
    trustpilotCheck(facts, domain),
    lotteryCheck(facts, domain),
    paymentCheck(facts, prizeContext),
  ].filter((entry): entry is Assessed => entry !== null);

  const has = (weight: Weight) => assessed.some((entry) => entry.weight === weight);
  const corroborations = assessed
    .filter((entry) => entry.weight === "corroborates")
    .reduce((sum, entry) => sum + (entry.corroborations ?? 1), 0);

  // A days-old domain is only a warning sign next to a prize or a request to pay.
  const newDomain = age.ageDays !== null && age.ageDays < 30;
  const asksToPay = assessed.some((entry) => entry.check.id === "payment");
  const oldEnough = age.ageDays === null || age.ageDays >= 180;
  const unconfirmed = assessed.some((entry) => entry.unconfirmed);

  let classification: SiteClassification;
  if (has("malicious")) classification = "confirmed_malicious";
  else if (has("suspicious") || (newDomain && (prizeContext || asksToPay)))
    classification = "suspicious";
  else if (corroborations >= 2 && oldEnough && !unconfirmed) classification = "no_known_issues";
  else classification = "unverified";

  const checks = assessed.map((entry) => entry.check);
  const raw = BASE_SCORE + checks.reduce((sum, entry) => sum + entry.impact, 0);
  const cap = SCORE_CAPS[classification];
  const trustScore = Math.max(0, Math.min(100, cap ? Math.min(raw, cap.max) : raw));

  return {
    url: facts.url,
    finalUrl: facts.trace.finalUrl,
    domain,
    classification,
    trustScore,
    scoreNote: cap && raw > cap.max ? `Capped at ${cap.max} because ${cap.why}.` : undefined,
    ...wording(classification, aboutLottery),
    checks,
    redirectChain: facts.trace.chain,
  };
}
