/** Yields each JSON value from a newline-delimited JSON byte stream. */
export async function* readNdjson<T>(body: ReadableStream<Uint8Array>): AsyncGenerator<T> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      buffer += decoder.decode(value, { stream: !done });
      const lines = buffer.split("\n");
      // Without a trailing newline the last piece is incomplete until the stream ends.
      buffer = done ? "" : (lines.pop() ?? "");
      for (const line of lines) {
        if (line.trim()) yield JSON.parse(line) as T;
      }
      if (done) return;
    }
  } finally {
    reader.releaseLock();
  }
}
