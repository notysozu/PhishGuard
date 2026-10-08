import { MAX_INPUT_CHARS } from "./types";

// Best-effort per-instance throttle so a public deployment can't be used to
// burn API credit. On serverless each instance counts separately.
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

/** Validates an analyze request. Returns the text to check, or an error response. */
export async function readInput(request: Request): Promise<string | Response> {
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
  return text.trim();
}
