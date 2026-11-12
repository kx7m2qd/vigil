/**
 * Scanned repos are untrusted, and so is everything engines echo back from them
 * (snippets, paths, messages). Before any of it reaches a terminal, strip:
 * - C0/C1 control characters, including ESC: blocks ANSI/OSC escape injection
 *   (rewriting the screen, fake hyperlinks, OSC 52 clipboard writes).
 * - Unicode bidi overrides/isolates: blocks "Trojan Source" text that displays
 *   differently from what it is (CVE-2021-42574).
 */
const UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

/** True if `text` contains anything sanitizeForTerminal would replace (tabs and newlines are fine). */
export function hasUnsafeChars(text: string): boolean {
  return new RegExp(UNSAFE.source).test(text);
}

export function sanitizeForTerminal(text: string): string {
  return text.replace(/\t/g, "  ").replace(/\r\n?/g, "\n").replace(UNSAFE, "\uFFFD");
}
