import assert from "node:assert/strict";
import { test } from "node:test";
import { SAMPLES } from "../app/samples";
import { registrableDomain, scanSignals, scoreSignals } from "../lib/phishguard/signals";

const score = (text: string) => scoreSignals(scanSignals(text));
const sample = (label: string) => SAMPLES.find((s) => s.label === label)!.text;

test("built-in scam samples are flagged, the ordinary one is not", () => {
  assert.ok(score(sample("Bank email")) >= 65);
  assert.ok(score(sample("Delivery text")) >= 30);
  assert.ok(score(sample("Lottery scam")) >= 65);
  assert.equal(score(sample("Ordinary message")), 0);
});

test("look-alike domain: brand name on someone else's domain", () => {
  const [signal] = scanSignals(
    "Log in at http://paypal.com.account-verify.secure-login.xyz/restore",
  );
  assert.equal(signal.category, "suspicious_link");
  assert.equal(signal.severity, "high");
  assert.match(signal.reason, /secure-login\.xyz/);
});

test("digit-for-letter swaps are caught", () => {
  const [signal] = scanSignals("Claim at www.amaz0n-rewards.top/claim");
  assert.equal(signal.severity, "high");
  assert.equal(signal.evidence, "www.amaz0n-rewards.top/claim");
});

test("a brand's own domain is not flagged", () => {
  assert.equal(score("Track your order at https://www.amazon.in/orders"), 0);
  assert.equal(score("Statement ready at https://www.paypal.com/activity"), 0);
});

test("link text that hides a different destination", () => {
  const signals = scanSignals("Sign in: [paypal.com](http://198.51.100.7/login)");
  assert.equal(signals.length, 1);
  assert.match(signals[0].reason, /actually opens 198\.51\.100\.7/);
});

test("spoofed sender: display name does not match the address", () => {
  const signals = scanSignals("From: PayPal Security <service@paypa1-secure-alerts.xyz>\nHello");
  assert.equal(signals[0].category, "spoofed_sender");
});

test("an email address is not mistaken for a link", () => {
  assert.equal(score("Send the notes to priya@gmail.com please"), 0);
});

test("evidence is always a verbatim quote, so the UI can highlight it", () => {
  for (const { text } of SAMPLES)
    for (const signal of scanSignals(text))
      assert.ok(text.includes(signal.evidence), signal.evidence);
});

test("repeated signals of one kind cannot max out the score alone", () => {
  assert.ok(score("urgent act now right away last chance today only final notice") < 65);
});

test("registrableDomain handles two-part suffixes", () => {
  assert.equal(registrableDomain("login.secure.example.co.uk"), "example.co.uk");
  assert.equal(registrableDomain("a.b.example.com"), "example.com");
});
