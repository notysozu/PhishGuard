import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { ApiError } from "@google/genai";
import { z } from "zod";
import {
  aiAvailable,
  createAgent,
  describeModelError,
  modelChain,
  type GenerateJson,
} from "../lib/phishguard/model";

const saved = { ...process.env };
afterEach(() => {
  process.env = { ...saved };
});

test("aiAvailable follows the environment at call time", () => {
  delete process.env.GEMINI_API_KEY;
  delete process.env.GOOGLE_API_KEY;
  assert.equal(aiAvailable(), false);
  process.env.GEMINI_API_KEY = "test-key";
  assert.equal(aiAvailable(), true);
  delete process.env.GEMINI_API_KEY;
  process.env.GOOGLE_API_KEY = "test-key";
  assert.equal(aiAvailable(), true);
});

test("model errors are described without leaking provider details", () => {
  const api = (status: number) => new ApiError({ status, message: "secret upstream detail" });
  assert.equal(describeModelError(api(403)), "the API key or request was rejected");
  assert.equal(describeModelError(api(429)), "rate limit reached");
  assert.equal(describeModelError(api(503)), "AI service error 503");
  assert.equal(
    describeModelError(z.string().safeParse(1).error),
    "the AI model returned an invalid answer",
  );
  assert.equal(describeModelError(new SyntaxError("x")), "the AI model returned an invalid answer");
  assert.equal(describeModelError(new Error("timed out")), "timed out");
  assert.equal(describeModelError("nope"), "unknown error");
});

const Answer = z.object({ ok: z.boolean() });
const request = { system: "s", user: "u", schema: Answer };
const outOfQuota = () => new ApiError({ status: 429, message: "quota" });

/** A fake model API: each model name maps to its answer or the error it throws. */
function fakeGenerate(byModel: Record<string, string | Error>) {
  const tried: string[] = [];
  const generate: GenerateJson = async ({ model }) => {
    tried.push(model);
    const answer = byModel[model];
    if (answer instanceof Error) throw answer;
    return answer;
  };
  return { generate, tried };
}

test("modelChain: primary then fallback, overridable, without duplicates", () => {
  delete process.env.PHISHGUARD_MODEL;
  delete process.env.PHISHGUARD_FALLBACK_MODEL;
  assert.deepEqual(modelChain(), ["gemini-2.5-flash", "gemini-2.5-flash-lite"]);
  process.env.PHISHGUARD_MODEL = "model-a";
  process.env.PHISHGUARD_FALLBACK_MODEL = "model-a";
  assert.deepEqual(modelChain(), ["model-a"]);
});

test("agent: uses the first model when it answers", async () => {
  const { generate, tried } = fakeGenerate({ a: '{"ok":true}', b: '{"ok":false}' });
  const agent = createAgent(generate, () => ["a", "b"]);
  assert.deepEqual(await agent(request), { ok: true });
  assert.deepEqual(tried, ["a"]);
});

test("agent: falls back to the next model when the first is out of quota", async () => {
  const { generate, tried } = fakeGenerate({ a: outOfQuota(), b: '{"ok":true}' });
  const agent = createAgent(generate, () => ["a", "b"]);
  assert.deepEqual(await agent(request), { ok: true });
  assert.deepEqual(tried, ["a", "b"]);
});

test("agent: when every model is out of quota, the quota error surfaces", async () => {
  const { generate } = fakeGenerate({ a: outOfQuota(), b: outOfQuota() });
  const agent = createAgent(generate, () => ["a", "b"]);
  await assert.rejects(agent(request), (err) => describeModelError(err) === "rate limit reached");
});

test("agent: a rejected key or bad request is not retried on another model", async () => {
  const { generate, tried } = fakeGenerate({
    a: new ApiError({ status: 403, message: "bad key" }),
    b: '{"ok":true}',
  });
  await assert.rejects(createAgent(generate, () => ["a", "b"])(request), ApiError);
  assert.deepEqual(tried, ["a"]);
});

test("agent: output that is not JSON, or breaks the schema, is rejected", async () => {
  const agent = (text: string) => createAgent(fakeGenerate({ a: text }).generate, () => ["a"]);
  await assert.rejects(agent("not json")(request), SyntaxError);
  await assert.rejects(agent('{"ok":"yes"}')(request), z.ZodError);
});
