import type { Signal, Severity } from "./types";

// Deterministic pattern scanner. It never fetches or opens anything in the
// message: links are only parsed as text.

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "t.ly",
]);

const RISKY_TLDS = new Set([
  "xyz", "top", "click", "link", "zip", "mov", "tk", "ml", "ga", "cf", "gq",
  "icu", "cam", "rest", "buzz", "monster", "live", "shop", "support", "info",
]);

const TWO_PART_TLDS = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.in", "net.in", "org.in",
  "gov.in", "co.nz", "co.za", "com.br", "co.jp", "com.sg", "com.mx",
]);

const BRANDS = [
  "paypal", "amazon", "apple", "icloud", "microsoft", "outlook", "office365",
  "google", "gmail", "netflix", "facebook", "instagram", "whatsapp", "linkedin",
  "dropbox", "docusign", "chase", "wellsfargo", "bankofamerica", "citibank",
  "hsbc", "barclays", "fedex", "dhl", "ups", "usps", "irs", "coinbase",
  "binance", "sbi", "hdfc", "icici", "paytm", "phonepe", "flipkart",
];

type Phrase = {
  re: RegExp;
  category: Signal["category"];
  severity: Severity;
  reason: string;
};

const PHRASES: Phrase[] = [
  {
    re: /\b(urgent(ly)?|immediate(ly)?|act now|right away|as soon as possible|within \d+ ?(hours?|hrs?|minutes?|mins?|days?)|final (notice|warning|reminder)|expires? (today|soon|in \d+)|last chance|today only)\b/gi,
    category: "urgency",
    severity: "medium",
    reason: "Pressures the reader to act quickly",
  },
  {
    re: /\b(account (has been |will be |is )?(suspended|locked|closed|disabled|restricted|terminated|deactivated|blocked)|will be (suspended|closed|terminated|blocked|deactivated)|legal action|arrest warrant|unauthorized (access|login|transaction|activity)|unusual (activity|sign-?in)|suspicious (activity|login))\b/gi,
    category: "threat",
    severity: "high",
    reason: "Threatens a loss or penalty to cause fear",
  },
  {
    re: /\b(verify your (account|identity|information|details)|confirm your (account|identity|password|details|information)|update your (payment|billing|account|card) (details|information|info|method)?|enter your (password|pin|otp|card)|share (the |your )?(otp|pin|password|cvv)|(social security|ssn|aadhaar|pan) (number|card)?|login credentials|one[- ]time (password|code))\b/gi,
    category: "credential_request",
    severity: "high",
    reason: "Asks for a password, code or personal details",
  },
  {
    re: /\b(gift cards?|wire transfer|western union|moneygram|bitcoin|crypto(currency)?|processing fee|customs fee|redelivery fee|pay (a |the )?(small )?fee|send (the )?money)\b/gi,
    category: "payment_request",
    severity: "high",
    reason: "Asks for money through a hard-to-reverse payment method",
  },
  {
    re: /\b(you('ve| have) won|congratulations|lottery|prize|free (gift|iphone|reward)|claim your (reward|prize|refund|gift)|selected as a winner|inheritance|100% (free|guaranteed))\b/gi,
    category: "too_good_to_be_true",
    severity: "medium",
    reason: "Promises an unexpected reward",
  },
  {
    re: /^\s*(dear|hello|hi) (valued )?(customer|user|client|member|account holder|sir\/?madam|sir or madam)\b/gim,
    category: "generic_greeting",
    severity: "low",
    reason: "Generic greeting instead of the recipient's name",
  },
  {
    re: /\b[\w-]+\.(exe|scr|zip|rar|iso|js|vbs|bat|docm|xlsm|html?|apk)\b/gi,
    category: "attachment",
    severity: "medium",
    reason: "Mentions a file type commonly used to deliver malware",
  },
];

const URL_RE =
  /\b(?:https?:\/\/|www\.)[^\s<>"')\]]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|info|xyz|top|click|link|co|io|me|ly|in|uk|us|ru|cn|tk|icu|shop|live|app|site|online)\b(?:\/[^\s<>"')\]]*)?/gi;

function parseHost(raw: string): string | null {
  try {
    const url = new URL(/^https?:\/\//i.test(raw) ? raw : `http://${raw}`);
    return url.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

export function registrableDomain(host: string): string {
  const labels = host.split(".");
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join(".");
  return TWO_PART_TLDS.has(lastTwo) ? labels.slice(-3).join(".") : lastTwo;
}

const deLeet = (s: string) =>
  s.replace(/0/g, "o").replace(/[1!|]/g, "l").replace(/3/g, "e")
    .replace(/5/g, "s").replace(/4|@/g, "a").replace(/rn/g, "m").replace(/vv/g, "w");

function impersonatedBrand(host: string): string | null {
  const domain = registrableDomain(host);
  const sld = domain.split(".")[0];
  const labels = host.split(/[.-]/);
  for (const brand of BRANDS) {
    if (sld === brand) return null; // the brand's own domain
    const matches = (s: string) =>
      brand.length <= 4 ? s === brand : s.includes(brand);
    if (labels.some((l) => matches(l) || matches(deLeet(l)))) return brand;
  }
  return null;
}

const RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2 };

/** One signal per link: the worst severity found, with every reason listed. */
function checkUrl(raw: string): Signal[] {
  const host = parseHost(raw);
  if (!host) return [];
  const found: { severity: Severity; reason: string }[] = [];
  const add = (severity: Severity, reason: string) => found.push({ severity, reason });

  const brand = impersonatedBrand(host);
  if (brand)
    add("high", `Link uses the name "${brand}" but actually goes to ${registrableDomain(host)}`);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host))
    add("high", "Link points to a raw IP address instead of a named website");
  if (host.includes("xn--"))
    add("high", "Link uses look-alike international characters (punycode)");
  if (/^https?:\/\/[^/]*@/i.test(raw))
    add("high", 'Link contains "@", which hides the real destination');
  if (SHORTENERS.has(registrableDomain(host)))
    add("medium", "Shortened link hides where it really goes");
  const tld = host.split(".").pop() ?? "";
  if (RISKY_TLDS.has(tld) && !brand)
    add("low", `Link ends in ".${tld}", an ending often used for throwaway sites`);
  if (host.split(".").length >= 5)
    add("medium", "Link has an unusually long chain of subdomains");
  if (/^http:\/\//i.test(raw))
    add("low", "Link is not encrypted (http instead of https)");

  if (!found.length) return [];
  found.sort((a, b) => RANK[b.severity] - RANK[a.severity]);
  return [
    {
      category: "suspicious_link",
      severity: found[0].severity,
      evidence: raw,
      reason: found.map((f) => f.reason).join("; "),
    },
  ];
}

/** `[paypal.com](http://evil.xyz)` or `<a href="http://evil.xyz">paypal.com</a>` */
function checkMismatchedLinks(text: string): Signal[] {
  const out: Signal[] = [];
  const patterns = [
    /\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/gi,
    /<a\b[^>]*href=["']?(https?:\/\/[^"'\s>]+)["']?[^>]*>([^<]+)<\/a>/gi,
  ];
  patterns.forEach((re, i) => {
    for (const m of text.matchAll(re)) {
      const [shown, target] = i === 0 ? [m[1], m[2]] : [m[2], m[1]];
      const shownHost = shown.match(URL_RE)?.[0];
      const a = shownHost && parseHost(shownHost);
      const b = parseHost(target);
      if (a && b && registrableDomain(a) !== registrableDomain(b)) {
        out.push({
          category: "suspicious_link",
          severity: "high",
          evidence: m[0],
          reason: `Link text shows ${a} but it actually opens ${b}`,
        });
      }
    }
  });
  return out;
}

/** `From: PayPal Support <help@paypa1-secure.xyz>` */
function checkSender(text: string): Signal[] {
  const out: Signal[] = [];
  const m = text.match(/^from:\s*(.*?)<?([\w.+-]+@([\w.-]+\.[a-z]{2,}))>?\s*$/im);
  if (!m) return out;
  const [line, display, , host] = m;
  const domain = registrableDomain(host.toLowerCase());
  const brand =
    impersonatedBrand(host.toLowerCase()) ??
    BRANDS.find(
      (b) =>
        new RegExp(`\\b${b}\\b`, "i").test(display) &&
        domain.split(".")[0] !== b
    );
  if (brand) {
    out.push({
      category: "spoofed_sender",
      severity: "high",
      evidence: line.trim(),
      reason: `Sender claims to be "${brand}" but the address is at ${domain}`,
    });
  }
  return out;
}

export function scanSignals(text: string): Signal[] {
  const signals: Signal[] = [...checkSender(text), ...checkMismatchedLinks(text)];

  // Links already reported as mismatched, and the domain half of an email
  // address, are not reported a second time.
  const covered = signals.map((s) => s.evidence).join("\n");
  const seenUrls = new Set<string>();
  for (const m of text.matchAll(URL_RE)) {
    const url = m[0].replace(/[.,;:!?]+$/, "");
    if (seenUrls.has(url) || text[m.index - 1] === "@" || covered.includes(url)) continue;
    seenUrls.add(url);
    signals.push(...checkUrl(url));
  }

  for (const p of PHRASES) {
    const seen = new Set<string>();
    for (const m of text.matchAll(p.re)) {
      const key = m[0].toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      signals.push({
        category: p.category,
        severity: p.severity,
        evidence: m[0].trim(),
        reason: p.reason,
      });
    }
  }
  return signals;
}

const WEIGHT: Record<Severity, number> = { low: 8, medium: 18, high: 32 };

export function scoreSignals(signals: Signal[]): number {
  // Repeats of the same category add less, so ten "urgent"s don't max the score.
  const perCategory = new Map<string, number>();
  let score = 0;
  for (const s of signals) {
    const n = perCategory.get(s.category) ?? 0;
    perCategory.set(s.category, n + 1);
    score += WEIGHT[s.severity] / (n + 1);
  }
  return Math.min(100, Math.round(score));
}
