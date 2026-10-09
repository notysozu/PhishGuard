import { ApiError, GoogleGenAI } from "@google/genai";
import { z } from "zod";

const apiKey = () => process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;

/** True when a model API key is configured. Read per call, not at import time. */
export const aiAvailable = () => Boolean(apiKey());

/**
 * Models to try, in order. The second is used only when the first is out of
 * quota or overloaded, so a busy day degrades to a lighter model instead of
 * to no AI at all.
 */
export function modelChain(): string[] {
  const primary = process.env.PHISHGUARD_MODEL || "gemini-2.5-flash";
  const fallback = process.env.PHISHGUARD_FALLBACK_MODEL || "gemini-2.5-flash-lite";
  return [...new Set([primary, fallback])];
}

/** Calls a model and returns output validated against `schema`. */
export type StructuredAgent = <T extends z.ZodType>(request: {
  system: string;
  user: string;
  schema: T;
}) => Promise<z.infer<T>>;

/** One model call that must return JSON text matching `jsonSchema`. */
export type GenerateJson = (request: {
  model: string;
  system: string;
  user: string;
  jsonSchema: unknown;
}) => Promise<string>;

const generateWithGemini: GenerateJson = async ({ model, system, user, jsonSchema }) => {
  const client = new GoogleGenAI({ apiKey: apiKey() });
  const response = await client.models.generateContent({
    model,
    contents: user,
    config: {
      systemInstruction: system,
      responseMimeType: "application/json",
      responseJsonSchema: jsonSchema,
    },
  });
  if (!response.text) {
    const reason = response.promptFeedback?.blockReason ?? response.candidates?.[0]?.finishReason;
    throw new Error(`The AI model returned no answer (${reason ?? "unknown reason"}).`);
  }
  return response.text;
};

/** Quota exhausted or service overloaded: another model may still answer. */
const isCapacityError = (err: unknown) =>
  err instanceof ApiError && (err.status === 429 || err.status === 503);

/** Builds an agent that tries each model in turn until one has capacity. */
export function createAgent(
  generate: GenerateJson = generateWithGemini,
  models: () => string[] = modelChain,
): StructuredAgent {
  return async ({ system, user, schema }) => {
    const jsonSchema = z.toJSONSchema(schema);
    let lastError: unknown;
    for (const model of models()) {
      try {
        const text = await generate({ model, system, user, jsonSchema });
        // The schema is enforced by the API; parse again so a bad response
        // can never reach the client as a malformed report.
        return schema.parse(JSON.parse(text));
      } catch (err) {
        if (!isCapacityError(err)) throw err;
        console.warn(`[phishguard] ${model} has no capacity, trying the next model`);
        lastError = err;
      }
    }
    throw lastError;
  };
}

export const callGemini = createAgent();

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
