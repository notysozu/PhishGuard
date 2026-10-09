import assert from "node:assert/strict";
import { test } from "node:test";
import { checkLottery } from "../lib/phishguard/site/lotteries";
import { assessSite, type SiteFacts } from "../lib/phishguard/site/trust";
import type { Signal, SiteCheckId, SiteReport } from "../lib/phishguard/types";

const NOW = new Date("2026-10-01T00:00:00Z");
const daysAgo = (days: number) => new Date(NOW.getTime() - days * 86_400_000).toISOString();

/** An unremarkable https site with nothing known about it. Override what the test is about. */
function facts(overrides: Partial<SiteFacts> = {}): SiteFacts {
  const url = overrides.url ?? "https://shop.example.com/";
  return {
    url,
    schemeAssumed: false,
    trace: { followed: true, chain: [url], finalUrl: url },
    registration: { state: "not_configured" },
    trustpilot: { state: "not_configured" },
    safeBrowsing: { state: "not_configured" },
    virusTotal: { state: "not_configured" },
    lottery: { kind: "not_lottery" },
    signals: [],
    now: NOW,
    ...overrides,
  };
}

const registered = (days: number, extra = {}) =>
  ({
    state: "found",
    data: {
      registeredAt: daysAgo(days),
      registrar: "Example Registrar",
      registrant: null,
      ...extra,
    },
  }) as const;

const check = (report: SiteReport, id: SiteCheckId) => report.checks.find((c) => c.id === id)!;

const signal = (category: Signal["category"], evidence: string): Signal => ({
  category,
  severity: "high",
  evidence,
  reason: "test",
});

test("with nothing known, a site is unverified at the neutral score", () => {
  const report = assessSite(facts({ url: "http://shop.example.com/" }));
  assert.equal(report.classification, "unverified");
  assert.equal(report.headline, "Unverified website");
  assert.equal(report.domain, "example.com");
});

test("the score is 50 plus every check's stated impact", () => {
  const report = assessSite(
    facts({
      registration: registered(400),
      virusTotal: { state: "found", data: { malicious: 0, suspicious: 0, total: 90 } },
      safeBrowsing: { state: "found", data: { threats: [] } },
    }),
  );
  const sum = report.checks.reduce((total, c) => total + c.impact, 50);
  assert.equal(report.trustScore, sum);
  assert.equal(report.scoreNote, undefined);
});

test("every check carries evidence, and unavailable checks never move the score", () => {
  const report = assessSite(facts());
  for (const c of report.checks) {
    assert.ok(c.summary.length > 0 && c.evidence.length > 20, c.id);
    if (c.outcome === "unavailable") assert.equal(c.impact, 0, c.id);
  }
  assert.equal(check(report, "trustpilot").outcome, "unavailable");
  assert.match(check(report, "trustpilot").evidence, /says nothing about the website either way/);
});

test("a Safe Browsing hit is confirmed malicious, whatever else looks good", () => {
  const report = assessSite(
    facts({
      registration: registered(4000),
      trustpilot: {
        state: "found",
        data: {
          name: "Shop",
          identifyingName: "example.com",
          trustScore: 4.8,
          reviews: 9000,
          profileUrl: "https://www.trustpilot.com/review/example.com",
        },
      },
      safeBrowsing: { state: "found", data: { threats: ["SOCIAL_ENGINEERING", "MALWARE"] } },
    }),
  );
  assert.equal(report.classification, "confirmed_malicious");
  assert.ok(report.trustScore <= 10);
  assert.match(check(report, "safe_browsing").summary, /phishing, malware/);
  assert.match(report.recommendedAction, /Do not open it/);
});

test("VirusTotal: several vendors confirm, one or two only caution, none corroborates", () => {
  const withVt = (malicious: number, suspicious = 0) =>
    assessSite(
      facts({
        registration: registered(800),
        virusTotal: { state: "found", data: { malicious, suspicious, total: 90 } },
      }),
    );
  assert.equal(withVt(5).classification, "confirmed_malicious");
  assert.equal(withVt(1).classification, "suspicious");
  assert.match(check(withVt(1), "virustotal").evidence, /false alarm/);
  assert.equal(withVt(0).classification, "no_known_issues");
  assert.match(check(withVt(0), "virustotal").evidence, /0 of 90 security vendors/);
});

test("a look-alike of a known brand is suspicious, and the evidence names both", () => {
  const url = "https://paypal.com.secure-login.xyz/restore";
  const report = assessSite(facts({ url, registration: registered(3000) }));
  assert.equal(report.classification, "suspicious");
  assert.ok(report.trustScore <= 45);
  const evidence = check(report, "impersonation").evidence;
  assert.match(evidence, /uses the name "paypal" but belongs to secure-login\.xyz/);
});

test("a brand's own long-established domain has no known problems", () => {
  const url = "https://www.amazon.in/orders";
  const report = assessSite(facts({ url, registration: registered(7000) }));
  assert.equal(report.classification, "no_known_issues");
  assert.match(check(report, "impersonation").summary, /amazon's own domain/);
});

test("domain age: brand new, fairly new, and established are scored differently", () => {
  const age = (days: number) =>
    check(assessSite(facts({ registration: registered(days) })), "domain_age");
  assert.equal(age(12).impact, -25);
  assert.match(age(12).summary, /Created only 12 days ago/);
  assert.equal(age(90).impact, -10);
  assert.equal(age(250).impact, 0);
  assert.equal(age(500).impact, 10);
  assert.equal(age(4000).impact, 15);
  assert.match(age(4000).evidence, /through Example Registrar/);
  assert.match(age(4000).evidence, /not public, which is normal/);
});

test("a days-old domain alone is unverified, but with a prize it is suspicious", () => {
  const plain = assessSite(facts({ registration: registered(10) }));
  assert.equal(plain.classification, "unverified", "new honest sites exist");

  const url = "https://lucky-winners.example.com/";
  const withPrize = assessSite(
    facts({
      url,
      registration: registered(10),
      lottery: checkLottery("You have won our jackpot!", url, "example.com"),
    }),
  );
  assert.equal(withPrize.classification, "suspicious");
});

test("a public owner is shown when the registry publishes one", () => {
  const report = assessSite(facts({ registration: registered(900, { registrant: "Shop Ltd" }) }));
  assert.match(check(report, "domain_age").evidence, /Registered to Shop Ltd\./);
});

test("an unregistered domain cannot be rated clean", () => {
  const report = assessSite(
    facts({
      registration: { state: "not_found" },
      trace: {
        followed: false,
        chain: ["https://shop.example.com/"],
        finalUrl: "https://shop.example.com/",
        note: "The website did not respond.",
      },
    }),
  );
  assert.equal(report.classification, "unverified");
  assert.match(check(report, "domain_age").summary, /No registration record found/);
  assert.equal(check(report, "https").outcome, "unavailable");
  assert.equal(check(report, "redirects").outcome, "unavailable");
});

test("Trustpilot is one signal: a great rating cannot clear a site on its own", () => {
  const profile = (trustScore: number, reviews: number) =>
    ({
      state: "found",
      data: {
        name: "Shop",
        identifyingName: "example.com",
        trustScore,
        reviews,
        profileUrl: "https://www.trustpilot.com/review/example.com",
      },
    }) as const;

  const glowing = assessSite(facts({ trustpilot: profile(4.9, 5000) }));
  assert.equal(glowing.classification, "unverified", "one corroboration is not enough");
  assert.equal(check(glowing, "trustpilot").impact, 10);
  assert.match(check(glowing, "trustpilot").evidence, /does not guarantee a website is legitimate/);

  assert.equal(check(assessSite(facts({ trustpilot: profile(4.9, 3) })), "trustpilot").impact, 0);
  assert.equal(
    check(assessSite(facts({ trustpilot: profile(1.6, 400) })), "trustpilot").impact,
    -15,
  );
});

test("a missing Trustpilot profile is neutral, not a warning", () => {
  const report = assessSite(facts({ trustpilot: { state: "not_found" } }));
  const trustpilot = check(report, "trustpilot");
  assert.equal(trustpilot.outcome, "neutral");
  assert.equal(trustpilot.impact, 0);
  assert.match(trustpilot.evidence, /not a warning sign by itself/);
});

test("lottery: the organizer's own site is verified", () => {
  const url = "https://www.powerball.com/";
  const report = assessSite(
    facts({ url, registration: registered(9000), lottery: checkLottery("", url, "powerball.com") }),
  );
  assert.equal(report.classification, "no_known_issues");
  assert.match(check(report, "lottery").summary, /Official website of Powerball/);
});

test("lottery: an unknown organizer is unverified with the organizer advice", () => {
  const url = "https://example-lottery.com/";
  const report = assessSite(
    facts({
      url,
      registration: registered(5000),
      lottery: checkLottery("", url, "example-lottery.com"),
    }),
  );
  assert.equal(report.classification, "unverified", "an old domain does not confirm a lottery");
  assert.equal(report.summary, "No reliable confirmation of the lottery organizer was found.");
  assert.match(
    report.recommendedAction,
    /organizer's official website before providing personal details/,
  );
  assert.ok(report.trustScore <= 65);
});

test("lottery: a fake Powerball site asking for a fee is suspicious, with both reasons", () => {
  const url = "http://powerball-winners-claim.top/release";
  const text = "You have won the Powerball lottery. Pay the processing fee and share the OTP.";
  const report = assessSite(
    facts({
      url,
      lottery: checkLottery(text, url, "powerball-winners-claim.top"),
      signals: [
        signal("payment_request", "processing fee"),
        signal("credential_request", "share the OTP"),
      ],
    }),
  );
  assert.equal(report.classification, "suspicious");
  assert.match(check(report, "lottery").evidence, /publishes results only on powerball\.com/);
  assert.match(check(report, "payment").evidence, /"processing fee", "share the OTP"/);
  assert.match(check(report, "payment").evidence, /never ask winners to pay first/);
  assert.equal(check(report, "https").impact, -10);
});

test("a payment request outside a prize context is a caution, not a verdict", () => {
  const report = assessSite(
    facts({
      registration: registered(3000),
      signals: [signal("payment_request", "redelivery fee")],
    }),
  );
  assert.equal(check(report, "payment").outcome, "caution");
  assert.equal(report.classification, "no_known_issues");
});

test("redirects: shortener to another site, same-site hop, and a dead shortener", () => {
  const traced = (chain: string[], note?: string) =>
    assessSite(
      facts({
        url: chain[0],
        registration: registered(3000),
        trace: { followed: true, chain, finalUrl: chain[chain.length - 1], note },
      }),
    );

  const shortened = traced(["https://bit.ly/abc", "https://shop.example.com/sale"]);
  assert.match(
    check(shortened, "redirects").summary,
    /Shortened link that leads to shop\.example\.com/,
  );
  assert.equal(shortened.domain, "example.com", "the destination is what gets rated");
  assert.equal(shortened.redirectChain.length, 2);

  const sameSite = traced(["http://example.com/", "https://www.example.com/"]);
  assert.equal(check(sameSite, "redirects").outcome, "neutral");

  const dead = traced(["https://bit.ly/abc"]);
  assert.match(check(dead, "redirects").summary, /does not reveal its destination/);
  assert.equal(dead.classification, "unverified", "bit.ly's own age says nothing about the target");
});

test("a shortener that hides a look-alike is caught at the destination", () => {
  const chain = ["https://bit.ly/abc", "https://paypa1-login.example.net/"];
  const report = assessSite(
    facts({ url: chain[0], trace: { followed: true, chain, finalUrl: chain[1] } }),
  );
  assert.equal(report.classification, "suspicious");
});

test("a score above its classification's ceiling is capped, and says why", () => {
  const url = "https://example-lottery.com/";
  const report = assessSite(
    facts({
      url,
      registration: registered(5000),
      virusTotal: { state: "found", data: { malicious: 0, suspicious: 0, total: 90 } },
      safeBrowsing: { state: "found", data: { threats: [] } },
      lottery: checkLottery("", url, "example-lottery.com"),
    }),
  );
  assert.equal(report.classification, "unverified");
  assert.equal(report.trustScore, 65);
  assert.match(report.scoreNote!, /Capped at 65 because nothing confirms who runs the website/);
});
