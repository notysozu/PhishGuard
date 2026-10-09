import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { ApiError } from "@google/genai";
import { z } from "zod";
import { aiAvailable, describeModelError } from "../lib/phishguard/model";

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
