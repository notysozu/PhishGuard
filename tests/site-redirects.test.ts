import assert from "node:assert/strict";
import { test } from "node:test";
import { BlockedUrlError, type HeadRequest } from "../lib/phishguard/site/net";
import { traceRedirects } from "../lib/phishguard/site/redirects";

/** A fake web: maps each address to the Location it redirects to, or to a final status. */
function web(routes: Record<string, string | number | Error>): HeadRequest & { seen: string[] } {
  const seen: string[] = [];
  const request: HeadRequest = async (url) => {
    seen.push(url.href);
    const route = routes[url.href];
    if (route instanceof Error) throw route;
    if (typeof route === "string") return { status: 302, location: route };
    return { status: route ?? 200, location: null };
  };
  return Object.assign(request, { seen });
}

test("a link with no redirects ends where it starts", async () => {
  const trace = await traceRedirects("https://example.com/", web({}));
  assert.deepEqual(trace, {
    followed: true,
    chain: ["https://example.com/"],
    finalUrl: "https://example.com/",
  });
});

test("follows a shortener through to its destination", async () => {
  const trace = await traceRedirects(
    "https://bit.ly/abc",
    web({
      "https://bit.ly/abc": "https://tracker.example/r?id=1",
      "https://tracker.example/r?id=1": "https://paypal.com.secure-login.xyz/restore",
    }),
  );
  assert.equal(trace.followed, true);
  assert.equal(trace.finalUrl, "https://paypal.com.secure-login.xyz/restore");
  assert.equal(trace.chain.length, 3);
  assert.equal(trace.note, undefined);
});

test("resolves relative redirects against the current address", async () => {
  const trace = await traceRedirects(
    "https://example.com/a/start",
    web({ "https://example.com/a/start": "../login" }),
  );
  assert.equal(trace.finalUrl, "https://example.com/login");
});

test("stops at a loop instead of going round forever", async () => {
  const trace = await traceRedirects(
    "https://a.example/",
    web({ "https://a.example/": "https://b.example/", "https://b.example/": "https://a.example/" }),
  );
  assert.match(trace.note!, /loop/);
  assert.equal(trace.finalUrl, "https://b.example/");
});

test("gives up after six redirects", async () => {
  const routes: Record<string, string> = {};
  for (let i = 0; i < 20; i++) routes[`https://hop${i}.example/`] = `https://hop${i + 1}.example/`;
  const request = web(routes);
  const trace = await traceRedirects("https://hop0.example/", request);
  assert.match(trace.note!, /Stopped after 6 redirects/);
  assert.equal(request.seen.length, 7, "the first address plus six redirects");
});

test("a redirect to an internal address is not followed", async () => {
  const request = web({
    "https://evil.example/": "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/": new BlockedUrlError(
      "The link points to a private or internal address.",
    ),
  });
  const trace = await traceRedirects("https://evil.example/", request);
  assert.equal(trace.followed, true, "the first hop did answer");
  assert.match(trace.note!, /private or internal address\. It was not opened\./);
});

test("an unreachable or invalid address is reported, not thrown", async () => {
  const down = await traceRedirects(
    "https://gone.example/",
    web({ "https://gone.example/": new Error("ENOTFOUND") }),
  );
  assert.equal(down.followed, false);
  assert.match(down.note!, /did not respond/);

  const invalid = await traceRedirects("not a url", web({}));
  assert.equal(invalid.followed, false);
  assert.match(invalid.note!, /not a valid web address/);
});

test("a redirect status with no Location header is treated as the end", async () => {
  const request: HeadRequest = async () => ({ status: 302, location: null });
  const trace = await traceRedirects("https://example.com/", request);
  assert.equal(trace.chain.length, 1);
});
