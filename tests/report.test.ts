import assert from "node:assert/strict";
import { test } from "node:test";
import { buildAiReport, buildAnalystReport, buildPatternReport } from "../lib/phishguard/report";
import { scanSignals } from "../lib/phishguard/signals";
import { RISK_THRESHOLDS, verdictForScore } from "../lib/phishguard/types";
import { SCAM_TEXT, detection, explanation } from "./fixtures";

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
  const report = buildPatternReport([], "rate limit reached");
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
