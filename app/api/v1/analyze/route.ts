import { phishGuardGraph } from "@/lib/phishguard/graph";
import { readInput } from "@/lib/phishguard/request";

/**
 * JSON API for the Android app and other clients.
 *
 *   POST /api/v1/analyze   { "text": "<message to check>" }
 *   200  { "report": Report }
 *   4xx/5xx  { "error": "<message safe to show the user>" }
 */
export async function POST(request: Request) {
  const input = await readInput(request);
  if (input instanceof Response) return input;

  try {
    const { report } = await phishGuardGraph.invoke({ input }, { signal: request.signal });
    return Response.json({ report }, { headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    console.error("[phishguard] analysis failed:", err);
    return Response.json(
      { error: "Something went wrong while checking this. Please try again." },
      { status: 500 },
    );
  }
}
