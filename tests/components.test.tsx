import assert from "node:assert/strict";
import { test } from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { MessageForm } from "../components/MessageForm";
import { ProgressSteps } from "../components/ProgressSteps";
import { ReportView } from "../components/ReportView";
import { buildAiReport, buildPatternReport } from "../lib/phishguard/report";
import { SCAM_TEXT, detection, explanation } from "./fixtures";

// Rendered to static HTML: enough to check structure and accessibility
// attributes without a browser.

const noop = () => {};
const count = (html: string, pattern: RegExp) => html.match(pattern)?.length ?? 0;

test("MessageForm: the textarea is labelled and described", () => {
  const html = renderToStaticMarkup(
    <MessageForm value="" onChange={noop} onSubmit={noop} busy={false} />,
  );
  assert.match(html, /<label for="message"[^>]*>Message to check<\/label>/);
  assert.match(html, /<textarea id="message"[^>]*aria-describedby="message-hint"/);
  assert.match(html, /<p id="message-hint"/);
  assert.match(html, /role="group" aria-labelledby="examples-label"/);
});

test("MessageForm: submit is disabled when empty or busy, enabled otherwise", () => {
  const submit = (value: string, busy: boolean) =>
    renderToStaticMarkup(
      <MessageForm value={value} onChange={noop} onSubmit={noop} busy={busy} />,
    ).match(/<button type="submit"[^>]*>[^<]*/)![0];
  assert.match(submit("", false), / disabled=""/);
  assert.match(submit("text", true), / disabled=""[^>]*>Checking…/);
  assert.doesNotMatch(submit("text", false), / disabled=""/);
});

test("ProgressSteps: marks the current step and gives every state a text label", () => {
  const html = renderToStaticMarkup(<ProgressSteps current="detect" />);
  assert.equal(count(html, /aria-current="step"/g), 1);
  assert.match(html, /aria-current="step"[^>]*>.*?Security analyst reviewing/);
  assert.match(html, /\(done\)/);
  assert.match(html, /\(in progress\)/);
  assert.match(html, /\(not started\)/);
});

test("ReportView: headings, meter and one linked highlight per warning sign", () => {
  const report = buildAiReport(detection, explanation);
  const html = renderToStaticMarkup(<ReportView report={report} message={SCAM_TEXT} />);

  assert.match(html, /<section[^>]*aria-labelledby="result-heading"/);
  assert.match(html, /<h2 id="result-heading"[^>]*>This is a scam\.<\/h2>/);
  assert.match(html, /role="meter"[^>]*aria-valuenow="92"/);
  assert.match(html, /aria-valuetext="92 out of 100: Likely a scam"/);

  assert.equal(count(html, /<mark/g), 2);
  assert.match(html, /<a href="#warning-sign-1"/);
  assert.match(html, /<li id="warning-sign-1"/);
  assert.match(html, /<span class="sr-only"> \(warning sign 1: Fake link\)<\/span>/);
  assert.match(html, /High risk/);
  assert.match(html, /Medium risk/);

  assert.match(html, /<h3[^>]*>What to do now<\/h3>/);
  assert.match(html, /If you already clicked, replied or paid/);
});

test("ReportView: a safe message shows no warning-sign section or recovery steps", () => {
  const report = buildPatternReport([]);
  const html = renderToStaticMarkup(<ReportView report={report} message="Dinner at 8?" />);
  assert.match(html, /Looks okay/);
  assert.doesNotMatch(html, /Why we think so/);
  assert.doesNotMatch(html, /If you already clicked/);
  assert.match(html, /scanner only/);
});

test("ReportView: message text is escaped, never rendered as HTML", () => {
  const message = '<img src=x onerror="alert(1)"> urgent';
  const report = buildPatternReport([
    { category: "urgency", severity: "medium", evidence: "urgent", reason: "Pressure" },
  ]);
  const html = renderToStaticMarkup(<ReportView report={report} message={message} />);
  assert.doesNotMatch(html, /<img/);
  assert.match(html, /&lt;img src=x/);
});
