import assert from "node:assert/strict";
import { test } from "node:test";
import { segmentMessage } from "../lib/phishguard/highlight";

const join = (segments: { text: string }[]) => segments.map((s) => s.text).join("");

test("highlights each quote and keeps the text intact", () => {
  const text = "Act now or your account will be closed.";
  const segments = segmentMessage(text, ["account will be closed", "Act now"]);
  assert.deepEqual(segments, [
    { text: "Act now", flag: 1 },
    { text: " or your " },
    { text: "account will be closed", flag: 0 },
    { text: "." },
  ]);
  assert.equal(join(segments), text);
});

test("matches case-insensitively but returns the original casing", () => {
  const [segment] = segmentMessage("URGENT notice", ["urgent"]);
  assert.deepEqual(segment, { text: "URGENT", flag: 0 });
});

test("skips quotes that are empty, missing or overlap an earlier highlight", () => {
  const text = "verify your identity today";
  const segments = segmentMessage(text, [
    "verify your identity",
    "",
    "not in text",
    "your identity",
  ]);
  assert.deepEqual(segments, [{ text: "verify your identity", flag: 0 }, { text: " today" }]);
});

test("no evidence yields one plain segment; empty text yields none", () => {
  assert.deepEqual(segmentMessage("hello", []), [{ text: "hello" }]);
  assert.deepEqual(segmentMessage("", ["x"]), []);
});
