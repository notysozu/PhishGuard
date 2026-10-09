import { MAX_INPUT_CHARS } from "./types";

/**
 * Sliding-window limiter held in memory. It is best-effort: on serverless,
 * each instance counts separately, so it slows abuse rather than stopping it.
 */
export function createRateLimiter(options: {
  windowMs: number;
  max: number;
  /** Upper bound on tracked clients, so the map cannot grow without limit. */
  maxClients?: number;
  now?: () => number;
}) {
  const { windowMs, max, maxClients = 10_000, now = Date.now } = options;
  const hits = new Map<string, number[]>();

  const prune = (cutoff: number) => {
    for (const [client, times] of hits) {
      if (times[times.length - 1] <= cutoff) hits.delete(client);
    }
  };

  return {
    /** Number of clients currently tracked. */
    get size() {
      return hits.size;
    },
    /** Records a request and returns true if the client is over the limit. */
    isLimited(client: string): boolean {
      const cutoff = now() - windowMs;
      if (hits.size >= maxClients) prune(cutoff);
      const recent = (hits.get(client) ?? []).filter((time) => time > cutoff);
      // Stop recording once over the limit, so a flood cannot grow the list.
      if (recent.length <= max) recent.push(now());
      hits.set(client, recent);
      return recent.length > max;
    },
  };
}

const limiter = createRateLimiter({ windowMs: 60_000, max: 10 });

const errorResponse = (error: string, status: number) => Response.json({ error }, { status });

const clientId = (request: Request) =>
  request.headers.get("x-forwarded-for")?.split(",")[0].trim() || "local";

/** Validates an analyze request. Returns the text to check, or an error response. */
export async function readInput(request: Request): Promise<string | Response> {
  if (limiter.isLimited(clientId(request))) {
    return errorResponse(
      "Too many checks in a short time. Please wait a minute and try again.",
      429,
    );
  }

  let text: unknown;
  try {
    text = (await request.json())?.text;
  } catch {
    return errorResponse("Invalid request.", 400);
  }
  if (typeof text !== "string" || !text.trim()) {
    return errorResponse("Paste a message or link to check.", 400);
  }
  if (text.length > MAX_INPUT_CHARS) {
    return errorResponse(
      `That's too long to check at once (limit ${MAX_INPUT_CHARS.toLocaleString("en")} characters).`,
      413,
    );
  }
  return text.trim();
}
