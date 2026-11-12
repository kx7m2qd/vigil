import { createHash } from "node:crypto";

/** Download a third-party benchmark input and refuse it unless it matches its pinned SHA-256. */
export async function downloadVerified(url: string, sha256: string, what: string): Promise<Buffer> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download failed: HTTP ${res.status} ${url}`);
  const bytes = Buffer.from(await res.arrayBuffer());
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== sha256) {
    throw new Error(`Checksum mismatch for ${what}: expected ${sha256}, got ${actual}. Refusing to use it.`);
  }
  return bytes;
}
