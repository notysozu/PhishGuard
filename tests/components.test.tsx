import assert from "node:assert/strict";
import { test } from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { MessageForm } from "../components/MessageForm";
import { ProgressSteps } from "../components/ProgressSteps";
import { ReportView } from "../components/ReportView";
import { SiteCheckCard } from "../components/SiteCheckCard";
import { buildAiReport, buildPatternReport } from "../lib/phishguard/report";
import { SCAM_TEXT, detection, explanation, siteReport } from "./fixtures";

// Rendered to static HTML: enough to check structure and accessibility
// attributes without a browser.

const noop = () => {};
const count = (html: string, pattern: RegExp) => html.match(pattern)?.length ?? 0;

test("MessageForm: the textarea is labelled and described", () => {
  const html = renderToStaticMarkup(
    <MessageForm value="" onChange={noop} onSubmit={noop} busy={false} />,
  );
  assert.match(html, /<label for="message"[^>]*>Message or website link to check<\/label>/);
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

test("SiteCheckCard: classification, trust score and the recommended action", () => {
  const html = renderToStaticMarkup(<SiteCheckCard site={siteReport()} />);
  assert.match(html, /<h3 id="site-heading"[^>]*>Website check<\/h3>/);
  assert.match(html, />Unverified<\/span>/);
  assert.match(html, /role="meter" aria-label="Trust score"[^>]*aria-valuenow="45"/);
  assert.match(html, /aria-valuetext="45 out of 100: Unverified"/);
  assert.match(html, /No reliable confirmation of the lottery organizer was found\./);
  assert.match(html, /Recommended action: <\/span>Verify the announcement/);
});

test("SiteCheckCard: every check shows its outcome, evidence and effect on the score", () => {
  const html = renderToStaticMarkup(<SiteCheckCard site={siteReport()} />);
  assert.match(html, />Warning<\/span><h5[^>]*>Domain age and ownership<\/h5>/);
  assert.match(html, /Created only 12 days ago/);
  assert.match(html, /−25<\/span><span class="sr-only">removes 25 points<\/span>/);
  assert.match(html, /\+5<\/span><span class="sr-only">adds 5 points<\/span>/);
  assert.match(html, />Not checked<\/span><h5[^>]*>Trustpilot reputation<\/h5>/);
  assert.match(html, /–<\/span><span class="sr-only">no effect on the score<\/span>/);
});

test("SiteCheckCard: source links open safely; the checked address is never a link", () => {
  const html = renderToStaticMarkup(<SiteCheckCard site={siteReport()} />);
  assert.match(
    html,
    /<a href="https:\/\/lookup\.icann\.org\/en\/lookup" target="_blank" rel="noopener noreferrer"/,
  );
  assert.match(html, /\(opens in a new tab\)/);
  assert.doesNotMatch(html, /href="https?:\/\/example-lottery\.com/);
  assert.match(html, /doesn&#x27;t guarantee a website is legitimate/);
});

test("SiteCheckCard: the redirect chain is listed only when the link moved", () => {
  const direct = renderToStaticMarkup(<SiteCheckCard site={siteReport()} />);
  assert.doesNotMatch(direct, /Where the link leads/);

  const chain = ["https://bit.ly/abc", "https://example-lottery.com/"];
  const moved = renderToStaticMarkup(<SiteCheckCard site={siteReport({ redirectChain: chain })} />);
  assert.match(moved, /Where the link leads/);
  assert.match(moved, /<li class="break-all">https:\/\/bit\.ly\/abc<\/li>/);
});

test("ReportView: shows the website check and the Not verified verdict", () => {
  const report = buildPatternReport([], { site: siteReport(), linkOnly: true });
  const html = renderToStaticMarkup(
    <ReportView report={report} message="https://example-lottery.com" />,
  );
  assert.match(html, />Not verified<\/p>/);
  assert.match(html, /Website check/);
  assert.match(html, /<h2 id="result-heading"[^>]*>Unverified website\.<\/h2>/);
});
