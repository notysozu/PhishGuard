import assert from "node:assert/strict";
import { before, test } from "node:test";
import { POST as analyzeStream } from "../app/api/analyze/route";
import { POST as analyzeJson } from "../app/api/v1/analyze/route";
import { readNdjson } from "../lib/phishguard/ndjson";
import type { Report, StreamEvent } from "../lib/phishguard/types";
import { SCAM_TEXT } from "./fixtures";

// These tests exercise the real routes and workflow without a model: with no
// API key the workflow takes its scanner-only path.
before(() => {
  delete process.env.GEMINI_API_KEY;
  delete process.env.GOOGLE_API_KEY;
  // No outbound requests about the link either: tests must not touch the network.
  process.env.PHISHGUARD_SITE_CHECKS = "off";
});

let nextIp = 0;
const post = (path: string, body: unknown) =>
  new Request(`http://test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": `10.1.0.${++nextIp}` },
    body: JSON.stringify(body),
  });

test("POST /api/v1/analyze returns a JSON report", async () => {
  const response = await analyzeJson(post("/api/v1/analyze", { text: SCAM_TEXT }));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const { report } = (await response.json()) as { report: Report };
  assert.equal(report.verdict, "dangerous");
  assert.equal(report.mode, "pattern");
  assert.ok(report.redFlags.length > 0);
});

test("POST /api/v1/analyze rejects an empty message with 400", async () => {
  const response = await analyzeJson(post("/api/v1/analyze", { text: "" }));
  assert.equal(response.status, 400);
  assert.equal(typeof (await response.json()).error, "string");
});

test("POST /api/analyze streams a step event, then the report", async () => {
  const response = await analyzeStream(post("/api/analyze", { text: SCAM_TEXT }));
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type")!, /application\/x-ndjson/);

  const events: StreamEvent[] = [];
  for await (const event of readNdjson<StreamEvent>(response.body!)) events.push(event);

  assert.deepEqual(events[0], { type: "step", step: "scan" });
  const last = events.at(-1)!;
  assert.equal(last.type, "report");
  assert.equal(last.type === "report" && last.report.verdict, "dangerous");
  assert.ok(!events.some((event) => event.type === "error"));
});

test("POST /api/analyze rejects bad input before streaming", async () => {
  const response = await analyzeStream(post("/api/analyze", { nope: true }));
  assert.equal(response.status, 400);
});
