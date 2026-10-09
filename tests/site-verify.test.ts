import assert from "node:assert/strict";
import { test } from "node:test";
import { scanSignals } from "../lib/phishguard/signals";
import { pickUrl, verifySite, type SiteDeps } from "../lib/phishguard/site/verify";

type Recorded = { traced: string[]; domains: string[]; safeBrowsing: string[][] };

/** Fake outside world: every lookup is "not configured" unless overridden. */
function deps(overrides: Partial<SiteDeps> = {}): SiteDeps & { recorded: Recorded } {
  const recorded: Recorded = { traced: [], domains: [], safeBrowsing: [] };
  return {
    recorded,
    traceRedirects: async (url) => {
      recorded.traced.push(url);
      return { followed: true, chain: [url], finalUrl: url };
    },
    lookupRegistration: async (domain) => {
      recorded.domains.push(domain);
      return { state: "not_configured" };
    },
    lookupTrustpilot: async () => ({ state: "not_configured" }),
    lookupSafeBrowsing: async (urls) => {
      recorded.safeBrowsing.push(urls);
      return { state: "not_configured" };
    },
    lookupVirusTotal: async () => ({ state: "not_configured" }),
    now: () => new Date("2026-10-01T00:00:00Z"),
    ...overrides,
  };
}

const verify = (text: string, world = deps()) => verifySite(text, scanSignals(text), world);

test("text with no link is not verified at all", async () => {
  const world = deps();
  assert.equal(await verify("Dinner at 8?", world), null);
  assert.equal(world.recorded.traced.length, 0);
});

test("pickUrl prefers the link the scanner found most suspicious", () => {
  const text =
    "Track at https://www.amazon.in/orders or pay at http://paypal.com.secure-login.xyz/pay";
  assert.equal(pickUrl(text, scanSignals(text)), "http://paypal.com.secure-login.xyz/pay");
  assert.equal(
    pickUrl("see https://a.example.com and https://b.example.com", []),
    "https://a.example.com",
  );
  assert.equal(pickUrl("no links here", []), null);
});

test("the destination after redirects is what gets looked up", async () => {
  const world = deps({
    traceRedirects: async (url) => ({
      followed: true,
      chain: [url, "https://shop.example.co.uk/sale"],
      finalUrl: "https://shop.example.co.uk/sale",
    }),
  });
  const site = await verify("https://bit.ly/abc", world);
  assert.equal(site!.domain, "example.co.uk");
  assert.deepEqual(world.recorded.domains, ["example.co.uk"]);
  assert.equal(site!.redirectChain.length, 2);
});

test("query strings are removed before a link is sent to a third party", async () => {
  const world = deps();
  await verify("https://shop.example.com/track?email=jane%40example.org&token=secret#frag", world);
  assert.deepEqual(world.recorded.safeBrowsing, [["https://shop.example.com/track"]]);
});

test("an address typed without a scheme tries https, then http", async () => {
  const world = deps({
    traceRedirects: async (url) => {
      world.recorded.traced.push(url);
      return url.startsWith("https://")
        ? { followed: false, chain: [url], finalUrl: url, note: "The website did not respond." }
        : { followed: true, chain: [url], finalUrl: url };
    },
  });
  const site = await verify("old-shop.example.com", world);
  assert.deepEqual(world.recorded.traced, [
    "https://old-shop.example.com",
    "http://old-shop.example.com",
  ]);
  assert.equal(site!.url, "http://old-shop.example.com");
  assert.equal(site!.checks.find((c) => c.id === "https")!.outcome, "caution");
});

test("a raw IP address skips the domain lookups instead of guessing", async () => {
  const world = deps();
  const site = await verify("http://8.8.8.8/login", world);
  assert.deepEqual(world.recorded.domains, []);
  assert.equal(site!.domain, "8.8.8.8");
  assert.equal(site!.classification, "suspicious");
  assert.match(site!.checks.find((c) => c.id === "domain_age")!.evidence, /raw IP address/);
});

test("the lottery sample is verified as a fake of a real lottery", async () => {
  const text =
    "Congratulations! Your number has won the Powerball lottery. Pay the processing fee at http://powerball-winners-claim.top/release";
  const site = await verify(text);
  assert.equal(site!.classification, "suspicious");
  assert.ok(site!.checks.some((c) => c.id === "lottery" && c.outcome === "bad"));
  assert.ok(site!.checks.some((c) => c.id === "payment" && c.outcome === "bad"));
});
