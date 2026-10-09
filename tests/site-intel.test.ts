import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import {
  lookupRegistration,
  lookupSafeBrowsing,
  lookupTrustpilot,
  lookupVirusTotal,
  resetIntelCache,
} from "../lib/phishguard/site/intel";

type Call = { url: string; init?: RequestInit };
let calls: Call[];
beforeEach(() => {
  calls = [];
  resetIntelCache();
});

/** A fake fetch that answers by URL prefix. A number is a bare status; an Error is thrown. */
function fakeFetch(routes: Record<string, unknown>): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    const key = Object.keys(routes).find((prefix) => url.startsWith(prefix));
    const answer = key === undefined ? 404 : routes[key];
    if (answer instanceof Error) throw answer;
    if (typeof answer === "number") return new Response(null, { status: answer });
    return Response.json(answer);
  }) as typeof fetch;
}

const BOOTSTRAP = {
  "https://data.iana.org/rdap/dns.json": {
    services: [[["com", "net"], ["https://rdap.example/com/"]]],
  },
};

const vcard = (...fields: [string, string][]) => [
  "vcard",
  fields.map(([name, value]) => [name, {}, "text", value]),
];

test("registration: reads the date, registrar and a public owner from RDAP", async () => {
  const result = await lookupRegistration(
    "shop.com",
    fakeFetch({
      ...BOOTSTRAP,
      "https://rdap.example/com/domain/shop.com": {
        events: [
          { eventAction: "expiration", eventDate: "2030-01-01T00:00:00Z" },
          { eventAction: "registration", eventDate: "2015-03-04T00:00:00Z" },
        ],
        entities: [
          { roles: ["registrar"], vcardArray: vcard(["fn", "Example Registrar, Inc."]) },
          { roles: ["registrant"], vcardArray: vcard(["fn", "Jane"], ["org", "Shop Ltd"]) },
        ],
      },
    }),
  );
  assert.deepEqual(result, {
    state: "found",
    data: {
      registeredAt: "2015-03-04T00:00:00Z",
      registrar: "Example Registrar, Inc.",
      registrant: "Shop Ltd",
    },
  });
});

test("registration: a redacted owner is reported as not public", async () => {
  const result = await lookupRegistration(
    "shop.com",
    fakeFetch({
      ...BOOTSTRAP,
      "https://rdap.example/com/domain/shop.com": {
        events: [{ eventAction: "registration", eventDate: "2015-03-04T00:00:00Z" }],
        entities: [{ roles: ["registrant"], vcardArray: vcard(["fn", "REDACTED FOR PRIVACY"]) }],
      },
    }),
  );
  assert.equal(result.state === "found" && result.data.registrant, null);
  assert.equal(result.state === "found" && result.data.registrar, null);
});

test("registration: unknown domain, unsupported ending and outage are told apart", async () => {
  assert.deepEqual(await lookupRegistration("nope.com", fakeFetch(BOOTSTRAP)), {
    state: "not_found",
  });

  const unsupported = await lookupRegistration("shop.zz", fakeFetch(BOOTSTRAP));
  assert.equal(unsupported.state, "error");
  assert.match(unsupported.state === "error" ? unsupported.reason : "", /no public registration/);

  resetIntelCache();
  const outage = await lookupRegistration(
    "shop.com",
    fakeFetch({ "https://data.iana.org": new Error("network down") }),
  );
  assert.equal(outage.state, "error");
});

test("registration: the server list is fetched once and reused", async () => {
  const fetchFn = fakeFetch(BOOTSTRAP);
  await lookupRegistration("a.com", fetchFn);
  await lookupRegistration("b.com", fetchFn);
  assert.equal(calls.filter((call) => call.url.includes("dns.json")).length, 1);
});

const PROFILE = {
  displayName: "Shop Ltd",
  name: { identifying: "shop.com" },
  websiteUrl: "https://www.shop.com",
  score: { trustScore: 4.3, stars: 4.5 },
  numberOfReviews: { total: 1200 },
};

test("Trustpilot: without a key nothing is requested and nothing is assumed", async () => {
  const result = await lookupTrustpilot("shop.com", "", fakeFetch({}));
  assert.deepEqual(result, { state: "not_configured" });
  assert.equal(calls.length, 0);
});

test("Trustpilot: returns the profile filed under the exact domain", async () => {
  const result = await lookupTrustpilot(
    "shop.com",
    "key-123",
    fakeFetch({ "https://api.trustpilot.com/v1/business-units/find?name=shop.com": PROFILE }),
  );
  assert.deepEqual(result, {
    state: "found",
    data: {
      name: "Shop Ltd",
      identifyingName: "shop.com",
      trustScore: 4.3,
      reviews: 1200,
      profileUrl: "https://www.trustpilot.com/review/shop.com",
    },
  });
  assert.deepEqual(calls[0].init?.headers, { apikey: "key-123" });
});

test("Trustpilot: a similarly named business on another domain is not a match", async () => {
  const other = {
    ...PROFILE,
    name: { identifying: "shop.co.uk" },
    websiteUrl: "https://shop.co.uk",
  };
  const result = await lookupTrustpilot(
    "shop.com",
    "key",
    fakeFetch({ "https://api.trustpilot.com": other }),
  );
  assert.deepEqual(result, { state: "not_found" });
});

test("Trustpilot: no profile, a rejected key and an outage are told apart", async () => {
  const lookup = (answer: unknown) =>
    lookupTrustpilot("shop.com", "key", fakeFetch({ "https://api.trustpilot.com": answer }));
  assert.deepEqual(await lookup(404), { state: "not_found" });
  assert.match(JSON.stringify(await lookup(403)), /rejected the API key/);
  assert.equal((await lookup(new Error("timeout"))).state, "error");
  assert.equal((await lookup(500)).state, "error");
});

test("Safe Browsing: lists threat types, and an empty answer means not listed", async () => {
  const listed = await lookupSafeBrowsing(
    ["http://bad.example/"],
    "key",
    fakeFetch({
      "https://safebrowsing.googleapis.com": {
        matches: [{ threatType: "SOCIAL_ENGINEERING" }, { threatType: "SOCIAL_ENGINEERING" }],
      },
    }),
  );
  assert.deepEqual(listed, { state: "found", data: { threats: ["SOCIAL_ENGINEERING"] } });
  const sent = JSON.parse(String(calls[0].init?.body));
  assert.deepEqual(sent.threatInfo.threatEntries, [{ url: "http://bad.example/" }]);

  const clean = await lookupSafeBrowsing(
    ["https://ok.example/"],
    "key",
    fakeFetch({ "https://safebrowsing.googleapis.com": {} }),
  );
  assert.deepEqual(clean, { state: "found", data: { threats: [] } });
});

test("Safe Browsing: no key means not configured; a failure is an error, not 'clean'", async () => {
  assert.deepEqual(await lookupSafeBrowsing(["https://x.example/"], "", fakeFetch({})), {
    state: "not_configured",
  });
  const failed = await lookupSafeBrowsing(
    ["https://x.example/"],
    "key",
    fakeFetch({ "https://safebrowsing.googleapis.com": 403 }),
  );
  assert.equal(failed.state, "error");
});

test("VirusTotal: counts vendors, and treats an unanalysed domain as no record", async () => {
  const stats = (values: Record<string, number>) => ({
    data: { attributes: { last_analysis_stats: values } },
  });
  const lookup = (answer: unknown, key = "key") =>
    lookupVirusTotal("shop.com", key, fakeFetch({ "https://www.virustotal.com": answer }));

  assert.deepEqual(
    await lookup(stats({ malicious: 4, suspicious: 1, harmless: 60, undetected: 29 })),
    { state: "found", data: { malicious: 4, suspicious: 1, total: 94 } },
  );
  assert.equal(calls[0].url, "https://www.virustotal.com/api/v3/domains/shop.com");
  assert.deepEqual(await lookup(stats({ malicious: 0, suspicious: 0, harmless: 0 })), {
    state: "not_found",
  });
  assert.deepEqual(await lookup(404), { state: "not_found" });
  assert.match(JSON.stringify(await lookup(429)), /request limit/);
  assert.match(JSON.stringify(await lookup(401)), /rejected the API key/);
  assert.deepEqual(await lookup(404, ""), { state: "not_configured" });
});
