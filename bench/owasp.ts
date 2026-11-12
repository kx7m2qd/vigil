/**
 * OWASP Benchmark for Python: score our rules per vulnerability category the way OWASP does
 * (score = true-positive rate − false-positive rate, per test file) and write
 * bench/results/owasp-python.json. Exits 1 if a category drops below bench/owasp-thresholds.json.
 *
 * The suite is GPL-3.0, so it is not vendored: it is downloaded at a pinned commit, verified
 * by SHA-256 like our engine binaries, and cached under the Vigil cache directory.
 */
import { access, mkdir, mkdtemp, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding } from "../src/core/finding.js";
import { DEFAULT_IGNORES } from "../src/core/ignore.js";
import { cacheRoot, resolveEngine } from "../src/engines/install.js";
import { runOpengrep } from "../src/engines/opengrep.js";
import { run } from "../src/engines/run.js";
import { downloadVerified } from "./fetch.js";

const BENCH_DIR = fileURLToPath(new URL(".", import.meta.url));
const RULES_DIR = fileURLToPath(new URL("../rules/python", import.meta.url));

const SUITE = {
  commit: "f1291485808b66e20ddb6b01b10dc71b3df8c8ba",
  sha256: "0defda4cce2ea7675fbeae5b059b4d7cca7d49232529367133feb1adfb529096",
  expected: "expectedresults-0.1.csv",
};
const URL_ = `https://codeload.github.com/OWASP-Benchmark/BenchmarkPython/tar.gz/${SUITE.commit}`;

interface Case {
  test: string;
  category: string;
  cwe: string;
  real: boolean;
}

interface CategoryScore {
  cwe: string;
  covered: boolean;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  tpr: number;
  fpr: number;
  score: number;
}

async function exists(path: string): Promise<boolean> {
  return access(path).then(
    () => true,
    () => false,
  );
}

/** Download, verify and extract the pinned suite once; later runs reuse the cache. */
async function fetchSuite(): Promise<string> {
  const parent = join(cacheRoot(), "bench");
  const dir = join(parent, `owasp-python-${SUITE.commit.slice(0, 12)}`);
  if (await exists(join(dir, SUITE.expected))) return dir;

  const bytes = await downloadVerified(URL_, SUITE.sha256, "OWASP Benchmark");
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const work = await mkdtemp(join(parent, ".staging-"));
  try {
    await writeFile(join(work, "suite.tar.gz"), bytes);
    const { code, stderr } = await run("tar", ["-xzf", join(work, "suite.tar.gz"), "-C", work, "--strip-components=1"]);
    if (code !== 0) throw new Error(`tar failed: ${stderr.trim()}`);
    await rm(join(work, "suite.tar.gz"));
    await rm(dir, { recursive: true, force: true });
    await rename(work, dir);
  } catch (e) {
    await rm(work, { recursive: true, force: true });
    throw e;
  }
  return dir;
}

async function loadCases(dir: string): Promise<Case[]> {
  const text = await readFile(join(dir, SUITE.expected), "utf8");
  return text
    .split("\n")
    .filter((line) => line.trim() && !line.startsWith("#"))
    .map((line) => {
      const [test = "", category = "", real = "", cwe = ""] = line.split(",").map((s) => s.trim());
      return { test, category, real: real === "true", cwe: `CWE-${cwe}` };
    });
}

/** CWEs our Python rules claim, read from their metadata. */
async function coveredCwes(): Promise<Set<string>> {
  const cwes = new Set<string>();
  for (const name of await readdir(RULES_DIR)) {
    if (!name.endsWith(".yml")) continue;
    for (const m of (await readFile(join(RULES_DIR, name), "utf8")).matchAll(/CWE-\d+/g)) cwes.add(m[0]);
  }
  return cwes;
}

const ratio = (num: number, den: number) => (den === 0 ? 0 : Math.round((num / den) * 1000) / 1000);

export function scoreCategories(cases: Case[], findings: Finding[], covered: Set<string>): Record<string, CategoryScore> {
  // A test file counts as flagged for its category if any finding in it carries that CWE.
  const flagged = new Set<string>();
  for (const f of findings) {
    const test = f.location.path.match(/(BenchmarkTest\d+)\.py$/)?.[1];
    if (test) for (const cwe of f.cwe ?? []) flagged.add(`${test} ${cwe}`);
  }
  const out: Record<string, CategoryScore> = {};
  for (const c of cases) {
    const s = (out[c.category] ??= { cwe: c.cwe, covered: covered.has(c.cwe), tp: 0, fp: 0, fn: 0, tn: 0, tpr: 0, fpr: 0, score: 0 });
    const hit = flagged.has(`${c.test} ${c.cwe}`);
    if (c.real) s[hit ? "tp" : "fn"]++;
    else s[hit ? "fp" : "tn"]++;
  }
  for (const s of Object.values(out)) {
    s.tpr = ratio(s.tp, s.tp + s.fn);
    s.fpr = ratio(s.fp, s.fp + s.tn);
    s.score = Math.round((s.tpr - s.fpr) * 1000) / 1000;
  }
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => a.localeCompare(b)));
}

async function main(): Promise<number> {
  const thresholds = JSON.parse(await readFile(join(BENCH_DIR, "owasp-thresholds.json"), "utf8")) as Record<string, number>;
  const dir = await fetchSuite();
  const cases = await loadCases(dir);
  const bin = await resolveEngine("opengrep", { autoInstall: true });
  const { findings, warnings } = await runOpengrep(bin, join(dir, "testcode"), DEFAULT_IGNORES);
  const categories = scoreCategories(cases, findings, await coveredCwes());

  const failures = Object.entries(thresholds)
    .filter(([cat, min]) => (categories[cat]?.score ?? 0) < min)
    .map(([cat, min]) => `${cat}: score ${categories[cat]?.score ?? 0} < gate ${min}`);
  const result = { pass: failures.length === 0, suite: { ...SUITE, url: URL_ }, thresholds, categories, failures, warnings };
  await mkdir(join(BENCH_DIR, "results"), { recursive: true });
  await writeFile(join(BENCH_DIR, "results", "owasp-python.json"), JSON.stringify(result, null, 2) + "\n");

  process.stdout.write(`${"category".padEnd(16)}${"cwe".padEnd(9)}  tp  fn  fp   tn    tpr    fpr  score\n`);
  for (const [cat, s] of Object.entries(categories)) {
    const row = [s.tp, s.fn, s.fp].map((n) => String(n).padStart(4)).join("") + String(s.tn).padStart(5);
    const rates = [s.tpr, s.fpr, s.score].map((n) => n.toFixed(3).padStart(7)).join("");
    process.stdout.write(`${cat.padEnd(16)}${s.cwe.padEnd(9)}${row}${rates}${s.covered ? "" : "  (no rule)"}\n`);
  }
  for (const f of failures) process.stdout.write(`  below gate: ${f}\n`);
  for (const w of warnings) process.stdout.write(`  warning: ${w}\n`);
  process.stdout.write(`\n→ ${result.pass ? "PASS" : "FAIL"}\n`);
  return result.pass ? 0 : 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().then(
    (code) => process.exit(code),
    (e: unknown) => {
      process.stderr.write(`bench:owasp: ${e instanceof Error ? e.message : String(e)}\n`);
      process.exit(2);
    },
  );
}
