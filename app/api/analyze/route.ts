import { phishGuardGraph } from "@/lib/phishguard/graph";
import { aiAvailable } from "@/lib/phishguard/model";
import { readInput } from "@/lib/phishguard/request";
import type { StreamEvent } from "@/lib/phishguard/types";

/**
 * Used by the web page. Streams one JSON object per line (NDJSON): a `step`
 * event as each workflow stage starts, then a final `report` or `error`.
 */
export async function POST(request: Request) {
  const input = await readInput(request);
  if (input instanceof Response) return input;

  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (event: StreamEvent) =>
        controller.enqueue(encoder.encode(JSON.stringify(event) + "\n"));
      try {
        send({ type: "step", step: "scan" });
        const updates = await phishGuardGraph.stream(
          { input },
          { streamMode: "updates", signal: request.signal },
        );
        for await (const update of updates) {
          if (update.scan) send({ type: "step", step: "verify" });
          if (update.verify_site && aiAvailable()) send({ type: "step", step: "detect" });
          if (update.detect?.detection) send({ type: "step", step: "explain" });
          const report = update.explain?.report ?? update.pattern_report?.report;
          if (report) send({ type: "report", report });
        }
      } catch (err) {
        console.error("[phishguard] analysis failed:", err);
        send({
          type: "error",
          message: "Something went wrong while checking this. Please try again.",
        });
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
