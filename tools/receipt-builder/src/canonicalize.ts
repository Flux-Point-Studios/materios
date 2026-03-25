import _canonicalize from "canonicalize";
// Handle CJS/ESM interop
const canonicalize = (_canonicalize as unknown as (input: unknown) => string | undefined);
import type { CanonicalLine } from "./types.js";

/**
 * Parse a JSONL string and canonicalize each line using RFC 8785 JCS.
 *
 * - Splits on `\n`, strips `\r`, filters empty lines.
 * - Each line is parsed as JSON then re-serialized via `canonicalize()`.
 */
export function canonicalizeJsonl(input: string): CanonicalLine[] {
  const rawLines = input.split("\n");
  const results: CanonicalLine[] = [];
  let index = 0;

  for (const raw of rawLines) {
    const trimmed = raw.replace(/\r/g, "");
    if (trimmed.length === 0) {
      continue;
    }

    const parsed = JSON.parse(trimmed);
    const canonical = canonicalize(parsed);

    if (canonical === undefined) {
      throw new Error(`Failed to canonicalize line ${index}: ${trimmed}`);
    }

    results.push({
      index,
      canonical,
      bytes: Buffer.from(canonical, "utf-8"),
    });

    index++;
  }

  return results;
}
