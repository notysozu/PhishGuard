import assert from "node:assert/strict";
import { test } from "node:test";
import { createRateLimiter, readInput } from "../lib/phishguard/request";
import { MAX_INPUT_CHARS } from "../lib/phishguard/types";

let nextIp = 0;
/** Each request gets its own client address so tests don't rate-limit each other. */
const post = (body: string, ip = `10.0.0.${++nextIp}`) =>
  new Request("http://test/api/analyze", {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": ip },
    body,
  });

async function errorOf(result: string | Response) {
  assert.ok(result instanceof Response);
  return { status: result.status, ...(await result.json()) };
}

test("returns the trimmed text for a valid request", async () => {
  assert.equal(await readInput(post(JSON.stringify({ text: "  hello  " }))), "hello");
});

test("rejects malformed JSON, missing text and blank text with 400", async () => {
  for (const body of ["{not json", "null", "{}", '{"text": 5}', '{"text": "   "}']) {
    assert.equal((await errorOf(await readInput(post(body)))).status, 400, body);
  }
});

test("rejects over-long input with 413", async () => {
  const body = JSON.stringify({ text: "a".repeat(MAX_INPUT_CHARS + 1) });
  const error = await errorOf(await readInput(post(body)));
  assert.equal(error.status, 413);
  assert.match(error.error, /20,000/);
});

test("the 11th request in a minute from one address gets 429", async () => {
  const body = JSON.stringify({ text: "hi" });
  for (let i = 0; i < 10; i++) assert.equal(await readInput(post(body, "203.0.113.9")), "hi");
  assert.equal((await errorOf(await readInput(post(body, "203.0.113.9")))).status, 429);
});

test("rate limiter: the window slides", () => {
  let now = 0;
  const limiter = createRateLimiter({ windowMs: 1000, max: 2, now: () => now });
  assert.equal(limiter.isLimited("a"), false);
  assert.equal(limiter.isLimited("a"), false);
  assert.equal(limiter.isLimited("a"), true);
  assert.equal(limiter.isLimited("b"), false, "other clients are unaffected");
  now = 1001;
  assert.equal(limiter.isLimited("a"), false, "old requests no longer count");
});

test("rate limiter: forgets idle clients once it is full", () => {
  let now = 0;
  const limiter = createRateLimiter({ windowMs: 1000, max: 1, maxClients: 2, now: () => now });
  limiter.isLimited("a");
  limiter.isLimited("b");
  assert.equal(limiter.size, 2);
  now = 5000;
  limiter.isLimited("c");
  assert.equal(limiter.size, 1, "a and b were idle past the window and are dropped");
});

test("rate limiter: a flood from one client does not grow its record", () => {
  const limiter = createRateLimiter({ windowMs: 1000, max: 3, now: () => 0 });
  for (let i = 0; i < 1000; i++) limiter.isLimited("a");
  assert.equal(limiter.isLimited("a"), true);
  assert.equal(limiter.size, 1);
});
