import type { CanonicalLine, Chunk } from "./types.js";

const DEFAULT_TARGET_SIZE = 65536; // 64KB

/**
 * Group canonical lines into chunks using greedy packing.
 *
 * - Default target is 64KB (65536 bytes).
 * - Lines are ATOMIC — never split across chunks.
 * - A single line larger than targetSize gets its own chunk.
 * - Chunk canonicalBytes = lines joined with `\n` (LF only), NO trailing newline.
 */
export function chunkLines(
  lines: CanonicalLine[],
  targetSize: number = DEFAULT_TARGET_SIZE,
): Chunk[] {
  if (lines.length === 0) {
    return [];
  }

  const chunks: Chunk[] = [];
  let currentLines: CanonicalLine[] = [];
  let currentSize = 0;
  let chunkIndex = 0;

  for (const line of lines) {
    const lineSize = line.bytes.length;

    // If adding this line would exceed target and we already have lines,
    // flush current chunk first.
    if (currentLines.length > 0 && currentSize + lineSize + 1 > targetSize) {
      // +1 for the LF separator
      chunks.push(buildChunk(chunkIndex, currentLines));
      chunkIndex++;
      currentLines = [];
      currentSize = 0;
    }

    currentLines.push(line);
    // Account for LF separator between lines (not before first line)
    currentSize += lineSize + (currentLines.length > 1 ? 1 : 0);
  }

  // Flush remaining lines
  if (currentLines.length > 0) {
    chunks.push(buildChunk(chunkIndex, currentLines));
  }

  return chunks;
}

function buildChunk(index: number, lines: CanonicalLine[]): Chunk {
  const joined = lines.map((l) => l.canonical).join("\n");
  return {
    index,
    lines: [...lines],
    canonicalBytes: Buffer.from(joined, "utf-8"),
  };
}
