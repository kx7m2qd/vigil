#!/usr/bin/env node
// Markdown job summary for the GitHub Action, built from Vigil's SARIF report.
// Usage: node action-summary.mjs <report.sarif> <exit-code>
import { readFileSync } from "node:fs";

const [file, code] = process.argv.slice(2);
const run = JSON.parse(readFileSync(file, "utf8")).runs?.[0] ?? {};
const rules = run.tool?.driver?.rules ?? [];
const results = run.results ?? [];

const SEVERITY = [
  ["critical", 9],
  ["high", 7],
  ["medium", 4],
  ["low", 0.1],
  ["info", 0],
];
const severityOf = (r) => {
  if (SEVERITY.some(([s]) => s === r.properties?.severity)) return r.properties.severity;
  const score = Number(rules[r.ruleIndex]?.properties?.["security-severity"] ?? 0);
  return SEVERITY.find(([, min]) => score >= min)[0];
};
// Finding text is untrusted (it quotes repo content): keep it to one line and out of the table syntax.
const cell = (s) =>
  String(s ?? "")
    .split("\n")[0]
    .replace(/[<>]/g, (c) => (c === "<" ? "&lt;" : "&gt;"))
    .replace(/\|/g, "\\|")
    .replace(/`/g, "'")
    .slice(0, 160);

const counts = Object.fromEntries(SEVERITY.map(([s]) => [s, 0]));
for (const r of results) counts[severityOf(r)]++;

const out = [];
out.push("## Vigil security scan", "");
const verdict = code === "0" ? "✅ Passed" : code === "1" ? "❌ Failed: findings at or above the fail-on level" : `⚠️ Scan error (exit ${code})`;
out.push(`**${verdict}** · ${results.length} finding${results.length === 1 ? "" : "s"}`, "");
out.push("| Critical | High | Medium | Low | Info |", "|---|---|---|---|---|");
out.push(`| ${counts.critical} | ${counts.high} | ${counts.medium} | ${counts.low} | ${counts.info} |`, "");

const order = Object.fromEntries(SEVERITY.map(([s], i) => [s, i]));
const top = [...results].sort((a, b) => order[severityOf(a)] - order[severityOf(b)]).slice(0, 25);
if (top.length) {
  out.push("| Severity | Location | Rule | Reachability | Message |", "|---|---|---|---|---|");
  for (const r of top) {
    const loc = r.locations?.[0]?.physicalLocation;
    const where = loc ? `${loc.artifactLocation?.uri}:${loc.region?.startLine ?? ""}` : "";
    out.push(`| ${severityOf(r)} | \`${cell(where)}\` | ${cell(rules[r.ruleIndex]?.name ?? r.ruleId)} | ${r.properties?.reachability ?? ""} | ${cell(r.message?.text)} |`);
  }
  if (results.length > top.length) out.push("", `…and ${results.length - top.length} more in the Security tab.`);
}
process.stdout.write(out.join("\n") + "\n");
