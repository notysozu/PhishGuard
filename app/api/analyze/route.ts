import { aiAvailable, phishGuardGraph } from "@/lib/phishguard/graph";
import { MAX_INPUT_CHARS, type StreamEvent } from "@/lib/phishguard/types";

// Best-effort per-instance throttle so a public demo can't be used to burn API credit.
const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 10;
const hits = new Map<string, number[]>();

function rateLimited(ip: string): boolean {
  const now = Date.now();
  const recent = (hits.get(ip) ?? []).filter((t) => now - t < WINDOW_MS);
  recent.push(now);
  hits.set(ip, recent);
  return recent.length > MAX_PER_WINDOW;
}

export async function POST(request: Request) {
  const ip = request.headers.get("x-forwarded-for")?.split(",")[0].trim() ?? "local";
  if (rateLimited(ip)) {
    return Response.json(
      { error: "Too many checks in a short time. Please wait a minute and try again." },
      { status: 429 }
    );
  }

  let text: unknown;
  try {
    ({ text } = await request.json());
  } catch {
    return Response.json({ error: "Invalid request." }, { status: 400 });
  }
  if (typeof text !== "string" || !text.trim()) {
    return Response.json({ error: "Paste a message or link to check." }, { status: 400 });
  }
  if (text.length > MAX_INPUT_CHARS) {
    return Response.json(
      { error: `That's too long to check at once (limit ${MAX_INPUT_CHARS.toLocaleString()} characters).` },
      { status: 413 }
    );
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const send = (event: StreamEvent) =>
        controller.enqueue(encoder.encode(JSON.stringify(event) + "\n"));
      try {
        send({ type: "step", step: "scan" });
        const updates = await phishGuardGraph.stream(
          { input: text.trim() },
          { streamMode: "updates", signal: request.signal }
        );
        for await (const update of updates) {
          if ("scan" in update && aiAvailable()) send({ type: "step", step: "detect" });
          if ("detect" in update && update.detect?.detection)
            send({ type: "step", step: "explain" });
          const report = update.explain?.report ?? update.pattern_report?.report;
          if (report) send({ type: "report", report });
        }
      } catch (err) {
        console.error("[phishguard] analysis failed:", err);
        send({ type: "error", message: "Something went wrong while checking this. Please try again." });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "application/x-ndjson; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}
