import { relative, resolve, sep } from "node:path";

/** Engine-reported path → path relative to the scan root, with forward slashes. */
export function toRelative(root: string, enginePath: string): string {
  return relative(root, resolve(root, enginePath)).split(sep).join("/");
}
