/** A run of the original message; `flag` is the index of the red flag it evidences. */
export type Segment = { text: string; flag?: number };

/**
 * Splits `text` into plain and highlighted runs, one highlight per evidence
 * quote. Quotes that are empty, not found, or overlap an earlier highlight are
 * skipped, so the segments always join back to the original text.
 */
export function segmentMessage(text: string, evidences: string[]): Segment[] {
  const lower = text.toLowerCase();
  const ranges: { start: number; end: number; flag: number }[] = [];

  evidences.forEach((evidence, flag) => {
    const needle = evidence.trim();
    if (!needle) return;
    let start = text.indexOf(needle);
    if (start < 0) start = lower.indexOf(needle.toLowerCase());
    if (start < 0) return;
    const end = start + needle.length;
    if (ranges.some((range) => start < range.end && end > range.start)) return;
    ranges.push({ start, end, flag });
  });
  ranges.sort((a, b) => a.start - b.start);

  const segments: Segment[] = [];
  let position = 0;
  for (const range of ranges) {
    if (range.start > position) segments.push({ text: text.slice(position, range.start) });
    segments.push({ text: text.slice(range.start, range.end), flag: range.flag });
    position = range.end;
  }
  if (position < text.length) segments.push({ text: text.slice(position) });
  return segments;
}
