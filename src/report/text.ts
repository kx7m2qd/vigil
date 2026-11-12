import { SEVERITY_ORDER, type Severity } from "../core/finding.js";
import { sanitizeForTerminal as safe } from "../core/sanitize.js";
import type { ScanResult } from "../scan.js";

const COLOR: Record<Severity, string> = {
  critical: "\x1b[1;35m",
  high: "\x1b[1;31m",
  medium: "\x1b[33m",
  low: "\x1b[36m",
  info: "\x1b[2m",
};
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";

export function toText(result: ScanResult, opts: { color: boolean }): string {
  const c = (code: string, s: string) => (opts.color ? `${code}${s}${RESET}` : s);
  const lines: string[] = [];

  // Every string from a finding is untrusted (it can come from the scanned code).
  for (const f of result.findings) {
    const where = safe(`${f.location.path}:${f.location.startLine}`);
    lines.push(`${c(COLOR[f.severity], f.severity.toUpperCase().padEnd(8))} ${c(BOLD, safe(f.title))}`);
    lines.push(`         ${where}  ${c(DIM, safe(`${f.engine}/${f.ruleId}${f.cwe.length ? "  " + f.cwe.join(",") : ""}`))}`);
    if (f.location.snippet) lines.push(`         ${c(DIM, "│")} ${safe(f.location.snippet).split("\n")[0]?.slice(0, 160)}`);
    if (f.dataflow && f.dataflow.length > 1) {
      const path = f.dataflow.map((s) => `${s.snippet ?? "?"} (L${s.line})`).join(" → ");
      lines.push(`         ${c(DIM, "flow:")} ${safe(path).replace(/\n/g, " ").slice(0, 200)}`);
    }
    lines.push(`         ${safe(f.message).split("\n")[0]?.slice(0, 240)}`);
    lines.push("");
  }

  const counts = SEVERITY_ORDER.map((s) => [s, result.findings.filter((f) => f.severity === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => c(COLOR[s], `${n} ${s}`));
  lines.push(
    result.findings.length
      ? `${c(BOLD, `${result.findings.length} findings`)}: ${counts.join(", ")}`
      : c(BOLD, "No findings."),
  );
  lines.push(
    c(DIM, result.engines.map((e) => `${e.engine} ${e.ok ? `${e.findings} in ${e.ms}ms` : "FAILED"}`).join(" · ")),
  );
  if (result.ignores.length) lines.push(c(DIM, `excluded by .vigilignore: ${safe(result.ignores.join(", ")).slice(0, 300)}`));
  for (const w of result.warnings) lines.push(c(COLOR.medium, `warning: ${safe(w)}`));
  return lines.join("\n");
}
