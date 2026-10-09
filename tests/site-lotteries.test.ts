import assert from "node:assert/strict";
import { test } from "node:test";
import { checkLottery } from "../lib/phishguard/site/lotteries";

const kind = (text: string, url: string, domain: string) => checkLottery(text, url, domain).kind;

test("an organizer's own domain is official, with or without surrounding text", () => {
  assert.equal(kind("", "https://www.powerball.com/", "powerball.com"), "official");
  assert.equal(
    kind(
      "See the EuroMillions results",
      "https://www.national-lottery.co.uk/results",
      "national-lottery.co.uk",
    ),
    "official",
  );
});

test("a win in a real lottery announced from another domain is impersonation", () => {
  const result = checkLottery(
    "Congratulations! You have won the Powerball lottery.",
    "http://powerball-winners-claim.top/release",
    "powerball-winners-claim.top",
  );
  assert.equal(result.kind, "impersonation");
  assert.equal(
    result.kind === "impersonation" && result.lottery.officialDomains[0],
    "powerball.com",
  );
});

test("the lottery's name inside the address is enough, even with no text", () => {
  assert.equal(
    kind("", "https://mega-millions-payout.xyz/", "mega-millions-payout.xyz"),
    "impersonation",
  );
});

test("merely mentioning a real lottery is not impersonation", () => {
  const result = checkLottery(
    "Powerball jackpot rolls over again, reports say",
    "https://news.example.com/lottery/powerball",
    "example.com",
  );
  assert.equal(result.kind, "unknown_organizer");
  assert.equal(result.kind === "unknown_organizer" && result.lottery?.name, "Powerball");
});

test("known scam themes are recognised", () => {
  assert.equal(
    kind(
      "Dear customer, your number won the KBC lottery of Rs 25 lakh",
      "https://kbc-win.in/",
      "kbc-win.in",
    ),
    "scam_theme",
  );
  assert.equal(
    kind("WhatsApp lucky draw 2026 winner notice", "https://wa-draw.top", "wa-draw.top"),
    "scam_theme",
  );
});

test("lottery talk with no organizer we know is unverified, not fake", () => {
  assert.equal(kind("", "https://example-lottery.com", "example-lottery.com"), "unknown_organizer");
  assert.equal(
    kind("Enter our Diwali lucky draw today", "https://shop.example.in/", "example.in"),
    "unknown_organizer",
  );
});

test("ordinary shopping and messages are not treated as lotteries", () => {
  assert.equal(
    kind("Your order has shipped", "https://www.amazon.in/orders", "amazon.in"),
    "not_lottery",
  );
  assert.equal(
    kind("Dinner at 8?", "https://maps.example.com/place", "example.com"),
    "not_lottery",
  );
});
