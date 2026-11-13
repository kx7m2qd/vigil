/**
 * Benchmark gate: scan bench/cases with our rules, score findings against the
 * `expect: <rule-id>` labels, write bench/results/latest.json, and exit 1 if
 * precision or recall drop below bench/thresholds.json. See bench/cases/README.md.
 */
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding } from "../src/core/finding.js";
import { DEFAULT_IGNORES, isIgnored } from "../src/core/ignore.js";
import { resolveEngine } from "../src/engines/install.js";
import { runOpengrep } from "../src/engines/opengrep.js";
import { runPkgrisk } from "../src/engines/pkgrisk/index.js";
import type { FetchLike } from "../src/engines/pkgrisk/registry.js";

const BENCH_DIR = fileURLToPath(new URL(".", import.meta.url));
const CASES_DIR = join(BENCH_DIR, "cases");
const RULES_DIR = join(BENCH_DIR, "..", "rules");
const SOURCE_EXT = /\.(js|jsx|mjs|cjs|ts|tsx|py)$/;
const LABEL = /(?:\/\/|#)\s*expect:\s*([a-z0-9-]+)/;

interface Label {
  ruleId: string;
  path: string;
  /** The line the label points at: the one directly below the comment. */
  line: number;
}

interface Counts {
  tp: number;
  fp: number;
  fn: number;
}

async function sourceFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true, recursive: true });
  return entries
    .filter((e) => e.isFile() && SOURCE_EXT.test(e.name))
    .map((e) => relative(CASES_DIR, join(e.parentPath, e.name)).split(sep).join("/"))
    .filter((p) => !isIgnored(p, DEFAULT_IGNORES))
    .sort();
}

async function loadLabels(files: string[]): Promise<Label[]> {
  const labels: Label[] = [];
  for (const path of files) {
    const lines = (await readFile(join(CASES_DIR, path), "utf8")).split("\n");
    lines.forEach((text, i) => {
      const m = text.match(LABEL);
      if (m?.[1]) labels.push({ ruleId: m[1], path, line: i + 2 });
    });
  }
  return labels;
}

/** Rule id → its CWE ids, read from rules/<lang>/<id>.yml. */
async function ruleCwes(): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>();
  for (const e of await readdir(RULES_DIR, { withFileTypes: true, recursive: true })) {
    if (!e.isFile() || !e.name.endsWith(".yml")) continue;
    const text = await readFile(join(e.parentPath, e.name), "utf8");
    out.set(e.name.slice(0, -".yml".length), [...new Set(text.match(/CWE-\d+/g) ?? [])]);
  }
  return out;
}

function onLine(f: Finding, l: Label): boolean {
  const end = f.location.endLine ?? f.location.startLine;
  return f.location.path === l.path && f.location.startLine <= l.line && l.line <= end;
}

/**
 * bench/cases/supply-chain: pkgrisk against recorded registry responses and a fixed clock, so the
 * gate stays offline and deterministic. Manifests can't hold comments, so the expected findings
 * live in expected.json as "<rule> <ecosystem> <name>".
 */
async function supplyChain(): Promise<{ expected: string[]; got: string[]; warnings: string[] }> {
  const dir = join(CASES_DIR, "supply-chain");
  const spec = JSON.parse(await readFile(join(dir, "expected.json"), "utf8")) as { now: string; expected: string[] };
  const docs = JSON.parse(await readFile(join(dir, "registry.json"), "utf8")) as Record<"npm" | "PyPI", Record<string, unknown>>;
  const fetch: FetchLike = async (url) => {
    const npm = /^https:\/\/registry\.npmjs\.org\/(.+)$/.exec(url);
    const pypi = /^https:\/\/pypi\.org\/pypi\/(.+)\/json$/.exec(url);
    const doc = npm ? docs.npm[decodeURIComponent(npm[1] as string)] : pypi ? docs.PyPI[decodeURIComponent(pypi[1] as string)] : undefined;
    return doc ? new Response(JSON.stringify(doc), { status: 200 }) : new Response("{}", { status: 404 });
  };
  const now = Date.parse(spec.now);
  const out = await runPkgrisk(dir, DEFAULT_IGNORES, { fetch, now: () => now, sleep: async () => {}, cacheDir: undefined });
  const got = out.findings.map((f) => `${f.ruleId} ${f.dependency?.ecosystem} ${f.dependency?.name}`);
  return { expected: spec.expected, got, warnings: out.warnings };
}

const ratio = (num: number, den: number) => (den === 0 ? 1 : Math.round((num / den) * 1000) / 1000);

async function main(): Promise<number> {
  const thresholds = JSON.parse(await readFile(join(BENCH_DIR, "thresholds.json"), "utf8")) as {
    precision: number;
    recall: number;
  };
  const labels = await loadLabels(await sourceFiles(CASES_DIR));
  const cwes = await ruleCwes();
  // A finding from a sibling rule for the same CWE counts, as in collapseOverlaps and bench:cves.
  const sibling = (f: Finding, l: Label) => f.cwe.some((c) => cwes.get(l.ruleId)?.includes(c));
  const bin = await resolveEngine("opengrep", { autoInstall: true });
  const { findings, warnings } = await runOpengrep(bin, CASES_DIR, DEFAULT_IGNORES);

  const perRule = new Map<string, Counts>();
  const bump = (rule: string, k: keyof Counts) => {
    const c = perRule.get(rule) ?? { tp: 0, fp: 0, fn: 0 };
    c[k]++;
    perRule.set(rule, c);
  };

  const matched = new Set<Label>();
  const falsePositives: string[] = [];
  const bySibling: string[] = [];
  for (const f of findings) {
    const open = labels.filter((l) => !matched.has(l) && onLine(f, l));
    const label = open.find((l) => l.ruleId === f.ruleId) ?? open.find((l) => sibling(f, l));
    if (label) {
      matched.add(label);
      bump(f.ruleId, "tp");
      if (label.ruleId !== f.ruleId) bySibling.push(`${label.path}:${label.line} ${label.ruleId} ← ${f.ruleId}`);
    } else {
      bump(f.ruleId, "fp");
      falsePositives.push(`${f.location.path}:${f.location.startLine} ${f.ruleId}`);
    }
  }
  const missed = labels.filter((l) => !matched.has(l));
  for (const l of missed) bump(l.ruleId, "fn");
  const missedText = missed.map((l) => `${l.path}:${l.line} ${l.ruleId}`);

  const sc = await supplyChain();
  let scTp = 0;
  for (const g of sc.got) {
    const rule = g.split(" ")[0] as string;
    if (sc.expected.includes(g)) {
      scTp++;
      bump(rule, "tp");
    } else {
      bump(rule, "fp");
      falsePositives.push(`supply-chain: ${g}`);
    }
  }
  for (const e of sc.expected.filter((x) => !sc.got.includes(x))) {
    bump(e.split(" ")[0] as string, "fn");
    missedText.push(`supply-chain: ${e}`);
  }
  warnings.push(...sc.warnings);

  const tp = matched.size + scTp;
  const precision = ratio(tp, tp + falsePositives.length);
  const recall = ratio(tp, labels.length + sc.expected.length);
  const pass = precision >= thresholds.precision && recall >= thresholds.recall;

  const result = {
    pass,
    precision,
    recall,
    thresholds,
    totals: {
      labels: labels.length + sc.expected.length,
      findings: findings.length + sc.got.length,
      tp,
      fp: falsePositives.length,
      fn: missedText.length,
    },
    rules: Object.fromEntries(
      [...perRule.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([rule, c]) => [rule, { ...c, precision: ratio(c.tp, c.tp + c.fp), recall: ratio(c.tp, c.tp + c.fn) }]),
    ),
    falsePositives: falsePositives.sort(),
    bySibling: bySibling.sort(),
    missed: missedText,
    warnings,
  };
  await mkdir(join(BENCH_DIR, "results"), { recursive: true });
  await writeFile(join(BENCH_DIR, "results", "latest.json"), JSON.stringify(result, null, 2) + "\n");

  for (const [rule, c] of Object.entries(result.rules)) {
    process.stdout.write(`${rule.padEnd(36)} tp ${c.tp}  fp ${c.fp}  fn ${c.fn}\n`);
  }
  for (const fp of result.falsePositives) process.stdout.write(`  false positive: ${fp}\n`);
  for (const m of result.missed) process.stdout.write(`  missed:         ${m}\n`);
  for (const b of result.bySibling) process.stdout.write(`  by sibling:     ${b}\n`);
  for (const w of warnings) process.stdout.write(`  warning: ${w}\n`);
  process.stdout.write(
    `\nprecision ${precision} (gate ${thresholds.precision})  recall ${recall} (gate ${thresholds.recall})  → ${pass ? "PASS" : "FAIL"}\n`,
  );
  return pass ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (e: unknown) => {
    process.stderr.write(`bench: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(2);
  },
);
