import { readFile } from "node:fs/promises";
import { join } from "node:path";

/** Always skipped, regardless of .vigilignore. */
export const DEFAULT_IGNORES = ["node_modules/", ".git/", "dist/", "build/", "vendor/", ".venv/", "venv/", "__pycache__/"];

/**
 * Load .vigilignore from the scan root. Each non-comment line is either a path
 * prefix ("bench/cases/") or a bare directory/file name ("fixtures") that
 * matches at any depth.
 */
export async function loadIgnorePatterns(root: string): Promise<string[]> {
  let text = "";
  try {
    text = await readFile(join(root, ".vigilignore"), "utf8");
  } catch {
    // No ignore file is fine.
  }
  const own = text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
  return [...DEFAULT_IGNORES, ...own];
}

export function isIgnored(relPath: string, patterns: string[]): boolean {
  const path = relPath.replace(/\\/g, "/").replace(/^\.\//, "");
  const segments = path.split("/");
  return patterns.some((raw) => {
    const p = raw.replace(/^\.\//, "");
    if (p.includes("/") && !/^[^/]+\/$/.test(p)) return path.startsWith(p);
    const name = p.replace(/\/$/, "");
    return segments.includes(name);
  });
}
