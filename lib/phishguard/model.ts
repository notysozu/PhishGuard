import { ApiError, GoogleGenAI } from "@google/genai";
import { z } from "zod";

const MODEL = process.env.PHISHGUARD_MODEL ?? "gemini-2.5-flash";

const apiKey = () => process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;

/** True when a model API key is configured. Read per call, not at import time. */
export const aiAvailable = () => Boolean(apiKey());

/** Calls a model and returns output validated against `schema`. */
export type StructuredAgent = <T extends z.ZodType>(request: {
  system: string;
  user: string;
  schema: T;
}) => Promise<z.infer<T>>;

export const callGemini: StructuredAgent = async ({ system, user, schema }) => {
  const client = new GoogleGenAI({ apiKey: apiKey() });
  const response = await client.models.generateContent({
    model: MODEL,
    contents: user,
    config: {
      systemInstruction: system,
      responseMimeType: "application/json",
      responseJsonSchema: z.toJSONSchema(schema),
    },
  });
  if (!response.text) {
    const reason = response.promptFeedback?.blockReason ?? response.candidates?.[0]?.finishReason;
    throw new Error(`The AI model returned no answer (${reason ?? "unknown reason"}).`);
  }
  // The schema is enforced by the API; parse again so a bad response can never
  // reach the client as a malformed report.
  return schema.parse(JSON.parse(response.text));
};

/** Short description of a model failure that is safe to show to the user. */
export function describeModelError(err: unknown): string {
  if (err instanceof ApiError) {
    if ([400, 401, 403].includes(err.status)) return "the API key or request was rejected";
    if (err.status === 429) return "rate limit reached";
    return `AI service error ${err.status}`;
  }
  if (err instanceof z.ZodError || err instanceof SyntaxError)
    return "the AI model returned an invalid answer";
  return err instanceof Error ? err.message : "unknown error";
}
