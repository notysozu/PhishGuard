import assert from "node:assert/strict";
import { test } from "node:test";
import {
  buildAiReport,
  buildAnalystReport,
  buildPatternReport,
  isLinkOnly,
  rate,
} from "../lib/phishguard/report";
import { scanSignals } from "../lib/phishguard/signals";
import { RISK_THRESHOLDS, verdictForScore } from "../lib/phishguard/types";
import { SCAM_TEXT, detection, explanation, siteReport } from "./fixtures";

test("verdict thresholds", () => {
  assert.equal(verdictForScore(RISK_THRESHOLDS.suspicious - 1), "likely_safe");
  assert.equal(verdictForScore(RISK_THRESHOLDS.suspicious), "suspicious");
  assert.equal(verdictForScore(RISK_THRESHOLDS.dangerous - 1), "suspicious");
  assert.equal(verdictForScore(RISK_THRESHOLDS.dangerous), "dangerous");
});

test("pattern report: scam text gets flags, steps and a scanner-only notice", () => {
  const report = buildPatternReport(scanSignals(SCAM_TEXT));
  assert.equal(report.mode, "pattern");
  assert.equal(report.verdict, "dangerous");
  assert.ok(report.redFlags.length >= 3);
  assert.ok(report.redFlags.every((flag) => SCAM_TEXT.includes(flag.evidence)));
  assert.ok(report.safetySteps.length > 0);
  assert.ok(report.ifAlreadyClicked.length > 0);
  assert.match(report.notice!, /No AI key is configured/);
});

test("pattern report: clean text is likely safe with no recovery steps", () => {
  const report = buildPatternReport(scanSignals("See you at 8 for dinner."));
  assert.equal(report.verdict, "likely_safe");
  assert.equal(report.riskScore, 0);
  assert.deepEqual(report.redFlags, []);
  assert.deepEqual(report.ifAlreadyClicked, []);
});

test("pattern report: names the AI failure when there was one", () => {
  const report = buildPatternReport([], { aiError: "rate limit reached" });
  assert.match(report.notice!, /AI analysis was unavailable \(rate limit reached\)/);
});

test("AI report: explainer wording, detector verdict and evidence", () => {
  const report = buildAiReport(detection, explanation);
  assert.equal(report.mode, "ai");
  assert.equal(report.verdict, "dangerous");
  assert.equal(report.riskScore, 92);
  assert.equal(report.headline, "This is a scam.");
  assert.deepEqual(
    report.redFlags.map((flag) => [flag.title, flag.evidence, flag.severity]),
    [
      ["Fake link", "http://paypal.com.secure-login.xyz/restore", "high"],
      ["Scare tactic", "account has been suspended", "medium"],
    ],
  );
  assert.equal(report.notice, undefined);
});

test("AI report: the explainer cannot add findings the detector did not make", () => {
  const invented = { findingIndex: 7, title: "Invented", explanation: "Not from the analyst." };
  const report = buildAiReport(detection, {
    ...explanation,
    redFlags: [...explanation.redFlags, invented],
  });
  assert.equal(report.redFlags.length, 2);
  assert.ok(!report.redFlags.some((flag) => flag.title === "Invented"));
});

test("AI report: out-of-range scores are clamped to 0-100", () => {
  assert.equal(buildAiReport({ ...detection, riskScore: 140 }, explanation).riskScore, 100);
  assert.equal(buildAiReport({ ...detection, riskScore: -3.2 }, explanation).riskScore, 0);
});

test("analyst report: detector verdict with template wording and a notice", () => {
  const report = buildAnalystReport(detection);
  assert.equal(report.verdict, "dangerous");
  assert.equal(report.redFlags[0].title, "Link isn't what it seems");
  assert.equal(report.redFlags[0].explanation, detection.findings[0].technicalReason);
  assert.match(report.notice!, /explainer was unavailable/);
});

test("isLinkOnly: a lone address, with or without punctuation, and nothing else", () => {
  assert.equal(isLinkOnly("https://example-lottery.com"), true);
  assert.equal(isLinkOnly("  example-lottery.com/win \n"), true);
  assert.equal(isLinkOnly("<https://example-lottery.com>."), true);
  assert.equal(isLinkOnly("Is https://example-lottery.com real?"), false);
  assert.equal(isLinkOnly("https://a.example.com https://b.example.com"), false);
  assert.equal(isLinkOnly("hello"), false);
});

test("rate: a message's own verdict stands when there is no website check", () => {
  assert.deepEqual(rate("suspicious", 40), { verdict: "suspicious", riskScore: 40 });
  assert.deepEqual(rate("likely_safe", 140), { verdict: "likely_safe", riskScore: 100 });
});

test("rate: the website can raise concern about a message but never lower it", () => {
  const malicious = siteReport({ classification: "confirmed_malicious", trustScore: 5 });
  const suspicious = siteReport({ classification: "suspicious", trustScore: 30 });
  const unverified = siteReport({ classification: "unverified", trustScore: 50 });
  const clean = siteReport({ classification: "no_known_issues", trustScore: 90 });

  assert.equal(rate("likely_safe", 5, { site: malicious }).verdict, "dangerous");
  assert.equal(rate("likely_safe", 5, { site: malicious }).riskScore, 95);
  assert.equal(rate("likely_safe", 5, { site: suspicious }).verdict, "suspicious");
  assert.equal(rate("likely_safe", 5, { site: unverified }).verdict, "unverified");
  assert.equal(rate("likely_safe", 5, { site: clean }).verdict, "likely_safe");

  // A scam message stays a scam even when it links to a respectable website.
  assert.deepEqual(rate("dangerous", 90, { site: clean }), { verdict: "dangerous", riskScore: 90 });
  assert.equal(rate("dangerous", 90, { site: unverified }).verdict, "dangerous");
  assert.equal(rate("suspicious", 40, { site: suspicious }).riskScore, 40);
});

test("rate: a bare address follows the website check exactly", () => {
  const linkOnly = true;
  const at = (classification: Parameters<typeof siteReport>[0]) =>
    rate("dangerous", 99, { site: siteReport(classification), linkOnly });

  assert.deepEqual(at({ classification: "unverified", trustScore: 45 }), {
    verdict: "unverified",
    riskScore: 55,
  });
  assert.equal(at({ classification: "no_known_issues", trustScore: 90 }).verdict, "likely_safe");
  assert.equal(at({ classification: "suspicious", trustScore: 0 }).verdict, "suspicious");
  assert.ok(at({ classification: "suspicious", trustScore: 0 }).riskScore < 65);
  assert.equal(at({ classification: "confirmed_malicious", trustScore: 10 }).verdict, "dangerous");
});

test("reports carry the website check, and analyst notes are combined", () => {
  const site = siteReport({ classification: "suspicious", trustScore: 20 });
  const calm = { ...detection, verdict: "likely_safe" as const, riskScore: 5 };
  assert.equal(buildAiReport(calm, explanation, { site }).site, site);
  assert.match(buildAiReport(calm, explanation, { site }).notice!, /website check below/);
  const analyst = buildAnalystReport(calm, { site });
  assert.match(analyst.notice!, /explainer was unavailable.*website check below/);
  assert.equal(buildPatternReport([], {}).site, undefined);
});

test("AI report: a finding the explainer skipped is kept with the analyst's note", () => {
  const partial = { ...explanation, redFlags: [explanation.redFlags[1]] };
  const report = buildAiReport(detection, partial);
  assert.equal(report.redFlags.length, 2, "no finding is dropped");
  assert.equal(report.redFlags[0].title, "Link isn't what it seems");
  assert.equal(report.redFlags[0].explanation, detection.findings[0].technicalReason);
  assert.equal(report.redFlags[1].title, "Scare tactic");
});
