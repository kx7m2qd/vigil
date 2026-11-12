import { fileURLToPath } from "node:url";
import { fingerprint, type Finding, type Severity } from "../core/finding.js";
import { toRelative } from "./paths.js";
import { run } from "./run.js";
import type { EngineOutput } from "./types.js";

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  affected?: {
    package?: { name?: string; ecosystem?: string };
    ranges?: { events?: { introduced?: string; fixed?: string }[] }[];
  }[];
  database_specific?: { severity?: string; cwe_ids?: string[] };
}

interface OsvPackage {
  package: { name: string; version: string; ecosystem: string };
  vulnerabilities?: OsvVuln[];
  groups?: { ids: string[]; aliases?: string[]; max_severity?: string }[];
}

export interface OsvOutput {
  results?: { source: { path: string; type: string }; packages?: OsvPackage[] }[];
}

const CONFIG = fileURLToPath(new URL("../../config/osv-scanner.toml", import.meta.url));

export function severityFromScore(score: string | undefined, label: string | undefined): Severity {
  const n = score ? Number.parseFloat(score) : Number.NaN;
  if (!Number.isNaN(n) && n > 0) {
    if (n >= 9) return "critical";
    if (n >= 7) return "high";
    if (n >= 4) return "medium";
    return "low";
  }
  switch (label?.toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "LOW":
      return "low";
    default:
      return "medium";
  }
}

function fixedVersions(vulns: OsvVuln[], pkg: OsvPackage["package"]): string[] {
  const fixed = new Set<string>();
  for (const v of vulns)
    for (const a of v.affected ?? []) {
      if (a.package?.name !== pkg.name) continue;
      for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) fixed.add(e.fixed);
    }
  return [...fixed];
}

/** One finding per advisory group (osv already merges aliases like GHSA + CVE). */
export function normalizeOsv(root: string, out: OsvOutput): Finding[] {
  const findings: Finding[] = [];
  for (const result of out.results ?? []) {
    const path = toRelative(root, result.source.path);
    for (const pkg of result.packages ?? []) {
      const vulns = pkg.vulnerabilities ?? [];
      const groups = pkg.groups?.length ? pkg.groups : vulns.map((v) => ({ ids: [v.id], aliases: v.aliases }));
      for (const g of groups) {
        const members = vulns.filter((v) => g.ids.includes(v.id));
        const primary = members[0];
        const ruleId = g.ids[0] ?? "unknown";
        const advisories = [...new Set([...g.ids, ...(g.aliases ?? [])])].sort();
        const fixed = fixedVersions(members, pkg.package);
        const { name, version, ecosystem } = pkg.package;
        const fixHint = fixed.length ? ` Upgrade to ${fixed.join(" or ")}.` : " No fixed version published yet.";
        findings.push({
          id: fingerprint("osv-scanner", ruleId, path, ecosystem, name, version),
          category: "dependency",
          engine: "osv-scanner",
          ruleId,
          title: primary?.summary ?? `${ruleId} in ${name}`,
          message: `${name}@${version} (${ecosystem}) is affected by ${advisories.join(", ")}.${fixHint}`,
          severity: severityFromScore("max_severity" in g ? g.max_severity : undefined, primary?.database_specific?.severity),
          location: { path, startLine: 1 },
          cwe: [...new Set(members.flatMap((m) => m.database_specific?.cwe_ids ?? []))],
          owasp: ["A06:2021 - Vulnerable and Outdated Components"],
          dependency: { name, version, ecosystem, advisories, fixedVersions: fixed },
        });
      }
    }
  }
  return findings;
}

export async function runOsv(bin: string, root: string): Promise<EngineOutput> {
  // Only package names and versions are sent to the OSV API, never source code.
  const res = await run(
    bin,
    [
      "scan",
      "source",
      "--format=json",
      // Our config, not the repo's osv-scanner.toml (which can ignore vulnerabilities).
      `--config=${CONFIG}`,
      // No call analysis: for some ecosystems it runs the repo's build scripts.
      "--no-call-analysis=all",
      // No transitive resolution: a manifest (e.g. pom.xml <repositories>) could
      // otherwise point the scanner at servers the repo chooses.
      "--no-resolve",
      "-r",
      "--",
      ".",
    ],
    { cwd: root },
  );
  // 0 = clean, 1 = vulnerabilities found, 128 = no packages/lockfiles found.
  if (res.code === 128) return { findings: [], warnings: [] };
  if (res.code !== 0 && res.code !== 1) {
    throw new Error(`osv-scanner exited ${res.code}: ${res.stderr.trim().slice(0, 500)}`);
  }
  return { findings: normalizeOsv(root, JSON.parse(res.stdout) as OsvOutput), warnings: [] };
}
