import type { Detection, Explanation } from "../lib/phishguard/types";

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
