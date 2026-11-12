/**
 * Real-world CVE fixes: for each case in bench/cves.json, scan the vulnerable file (parent of the
 * fix commit) and the fixed file, and check that a rule for the advisory's CWE fires on the
 * vulnerable line but not on the fixed one. Writes bench/results/cves.json; exits 1 below bench/cve-thresholds.json.
 *
 * Files are downloaded from the upstream repos at pinned commits and verified by SHA-256 (never
 * vendored: they carry their projects' own licenses), then cached under the Vigil cache directory.
 */
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding } from "../src/core/finding.js";
import { DEFAULT_IGNORES } from "../src/core/ignore.js";
import { cacheRoot, resolveEngine } from "../src/engines/install.js";
import { runOpengrep } from "../src/engines/opengrep.js";
import { downloadVerified } from "./fetch.js";

const BENCH_DIR = fileURLToPath(new URL(".", import.meta.url));

interface PinnedFile {
  commit: string;
  sha256: string;
  /** The line the advisory's fix changed: the sink in the vulnerable file, its replacement in the fixed one. */
  line: number;
}

export interface CveCase {
  id: string;
  cve: string | null;
  package: string;
  cwe: string[];
  summary: string;
  advisory: string;
  repo: string;
  path: string;
  /** The rule written for this class; any rule with one of the case's CWEs counts as a detection. */
  rule: string;
  vulnerable: PinnedFile;
  fixed: PinnedFile;
}

export interface CveOutcome {
  id: string;
  rule: string;
  /** Rules that fired on the vulnerable line. */
  detectedBy: string[];
  detected: boolean;
  fixStillFlagged: boolean;
}

const VERSIONS = ["vulnerable", "fixed"] as const;

/** Where a case's file lives inside the scan root, relative to it. */
export const casePath = (c: CveCase, version: (typeof VERSIONS)[number]) => `${c.id}/${version}/${c.path}`;

async function exists(path: string): Promise<boolean> {
  return access(path).then(
    () => true,
    () => false,
  );
}

async function fetchCases(root: string, cases: CveCase[]): Promise<void> {
  for (const c of cases) {
    for (const version of VERSIONS) {
      const target = join(root, casePath(c, version));
      if (await exists(target)) continue;
      const pin = c[version];
      const url = `https://raw.githubusercontent.com/${c.repo}/${pin.commit}/${c.path}`;
      const bytes = await downloadVerified(url, pin.sha256, `${c.id} (${version})`);
      await mkdir(dirname(target), { recursive: true, mode: 0o700 });
      await writeFile(target, bytes);
    }
  }
}

const covers = (f: Finding, c: CveCase, version: (typeof VERSIONS)[number]) =>
  f.cwe.some((cwe) => c.cwe.includes(cwe)) &&
  f.location.path === casePath(c, version) &&
  f.location.startLine <= c[version].line &&
  c[version].line <= (f.location.endLine ?? f.location.startLine);

export function scoreCves(cases: CveCase[], findings: Finding[]): CveOutcome[] {
  return cases.map((c) => {
    const detectedBy = [...new Set(findings.filter((f) => covers(f, c, "vulnerable")).map((f) => f.ruleId))];
    return {
      id: c.id,
      rule: c.rule,
      detectedBy,
      detected: detectedBy.length > 0,
      fixStillFlagged: findings.some((f) => covers(f, c, "fixed")),
    };
  });
}

async function main(): Promise<number> {
  const cases = JSON.parse(await readFile(join(BENCH_DIR, "cves.json"), "utf8")) as CveCase[];
  const thresholds = JSON.parse(await readFile(join(BENCH_DIR, "cve-thresholds.json"), "utf8")) as {
    recall: number;
    maxFixStillFlagged: number;
  };
  // Cached files are verified when downloaded and keyed by commit, so they never go stale.
  const root = join(cacheRoot(), "bench", "cves");
  await fetchCases(root, cases);
  const bin = await resolveEngine("opengrep", { autoInstall: true });
  const { findings, warnings } = await runOpengrep(bin, root, DEFAULT_IGNORES);
  const outcomes = scoreCves(cases, findings);

  const detected = outcomes.filter((o) => o.detected).length;
  const fixStillFlagged = outcomes.filter((o) => o.fixStillFlagged).length;
  const recall = Math.round((detected / outcomes.length) * 1000) / 1000;
  const pass = recall >= thresholds.recall && fixStillFlagged <= thresholds.maxFixStillFlagged;
  const result = { pass, recall, detected, fixStillFlagged, total: outcomes.length, thresholds, cases: outcomes, warnings };
  await mkdir(join(BENCH_DIR, "results"), { recursive: true });
  await writeFile(join(BENCH_DIR, "results", "cves.json"), JSON.stringify(result, null, 2) + "\n");

  for (const o of outcomes) {
    const mark = o.detected ? (o.fixStillFlagged ? "~" : "✓") : "✗";
    const by = o.detectedBy.join(", ");
    const note = o.detected ? (o.fixStillFlagged ? `detected by ${by}, but fix still flagged` : `detected by ${by}`) : "missed";
    process.stdout.write(`${mark} ${o.id}  ${o.rule.padEnd(28)} ${note}\n`);
  }
  for (const w of warnings) process.stdout.write(`  warning: ${w}\n`);
  process.stdout.write(
    `\ndetected ${detected}/${outcomes.length} (recall ${recall}, gate ${thresholds.recall})  ` +
      `fix still flagged ${fixStillFlagged} (gate ≤ ${thresholds.maxFixStillFlagged})  → ${pass ? "PASS" : "FAIL"}\n`,
  );
  return pass ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().then(
    (code) => process.exit(code),
    (e: unknown) => {
      process.stderr.write(`bench:cves: ${e instanceof Error ? e.message : String(e)}\n`);
      process.exit(2);
    },
  );
}
