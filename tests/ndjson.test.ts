import assert from "node:assert/strict";
import { test } from "node:test";
import { readNdjson } from "../lib/phishguard/ndjson";

function streamOf(...chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
}

async function collect<T>(stream: ReadableStream<Uint8Array>): Promise<T[]> {
  const values: T[] = [];
  for await (const value of readNdjson<T>(stream)) values.push(value);
  return values;
}

test("parses one value per line", async () => {
  assert.deepEqual(await collect(streamOf('{"a":1}\n{"a":2}\n')), [{ a: 1 }, { a: 2 }]);
});

test("reassembles a line split across chunks", async () => {
  assert.deepEqual(await collect(streamOf('{"type":"st', 'ep"}\n{"type"', ':"report"}\n')), [
    { type: "step" },
    { type: "report" },
  ]);
});

test("reads a final line that has no trailing newline, and skips blank lines", async () => {
  assert.deepEqual(await collect(streamOf('{"a":1}\n\n{"a":2}')), [{ a: 1 }, { a: 2 }]);
});

test("keeps multi-byte characters split across chunks", async () => {
  const bytes = new TextEncoder().encode('{"t":"€"}\n');
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes.slice(0, 7));
      controller.enqueue(bytes.slice(7));
      controller.close();
    },
  });
  assert.deepEqual(await collect(stream), [{ t: "€" }]);
});

test("rejects on malformed JSON", async () => {
  await assert.rejects(collect(streamOf("not json\n")), SyntaxError);
});
