import type { Detection, Explanation, SiteReport } from "../lib/phishguard/types";

export const SCAM_TEXT =
  "Urgent: your account has been suspended. Verify at http://paypal.com.secure-login.xyz/restore";

export const detection: Detection = {
  verdict: "dangerous",
  riskScore: 92,
  findings: [
    {
      category: "suspicious_link",
      severity: "high",
      evidence: "http://paypal.com.secure-login.xyz/restore",
      technicalReason: "Brand name used as a subdomain of an unrelated domain.",
    },
    {
      category: "threat",
      severity: "medium",
      evidence: "account has been suspended",
      technicalReason: "Threat of account loss.",
    },
  ],
  reassuringSigns: [],
};

export const explanation: Explanation = {
  headline: "This is a scam.",
  summary: "It pretends to be PayPal.",
  redFlags: [
    { findingIndex: 0, title: "Fake link", explanation: "The link goes somewhere else." },
    { findingIndex: 1, title: "Scare tactic", explanation: "It tries to frighten you." },
  ],
  safetySteps: ["Open the PayPal app yourself."],
  ifAlreadyClicked: ["Change your password."],
};

/** A website report with sensible defaults; override what the test is about. */
export const siteReport = (overrides: Partial<SiteReport> = {}): SiteReport => ({
  url: "https://example-lottery.com/",
  finalUrl: "https://example-lottery.com/",
  domain: "example-lottery.com",
  classification: "unverified",
  trustScore: 45,
  headline: "Unverified website",
  summary: "No reliable confirmation of the lottery organizer was found.",
  recommendedAction:
    "Verify the announcement on the organizer's official website before providing personal details or paying any fees.",
  checks: [
    {
      id: "domain_age",
      label: "Domain age and ownership",
      outcome: "bad",
      summary: "Created only 12 days ago",
      evidence: "example-lottery.com was registered on 1 January 2026.",
      impact: -25,
      source: { name: "ICANN registration lookup", url: "https://lookup.icann.org/en/lookup" },
    },
    {
      id: "trustpilot",
      label: "Trustpilot reputation",
      outcome: "unavailable",
      summary: "Not checked",
      evidence: "This PhishGuard server has no Trustpilot API key, so this check was skipped.",
      impact: 0,
    },
    {
      id: "https",
      label: "Secure connection (HTTPS)",
      outcome: "good",
      summary: "Uses an encrypted connection",
      evidence: "The address starts with https.",
      impact: 5,
    },
  ],
  redirectChain: ["https://example-lottery.com/"],
  ...overrides,
});
