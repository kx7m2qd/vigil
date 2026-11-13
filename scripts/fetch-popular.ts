/**
 * Refresh data/popular-npm.txt and data/popular-pypi.txt (typosquat targets for pkgrisk).
 * Run by hand: `npm run data:popular`. Never runs at scan time.
 *
 * Both sources are pinned. npm-high-impact is an exact version tarball whose registry
 * `dist.integrity` is verified; top-pypi-packages is a raw URL at a fixed commit, and its
 * SHA-256 is compared with the one recorded in data/SOURCES.json when the pin is unchanged.
 * Bumping a pin means editing the constants below and reviewing the diff of the data files.
 */
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { run } from "../src/engines/run.js";

const NPM_HIGH_IMPACT_VERSION = "1.13.0";
const NPM_HIGH_IMPACT_INTEGRITY =
  "sha512-Dngjb2fyZfj4/7aZ+9kGGGK/IWnBhb45nzHX1ECxi26vXixkKzdixCB81XTwQzyAwc4d39VbcTL+rlS+d7VETA==";
const NPM_TARBALL = `https://registry.npmjs.org/npm-high-impact/-/npm-high-impact-${NPM_HIGH_IMPACT_VERSION}.tgz`;

const PYPI_COMMIT = "29c0d4c38c28c0e6b99e73fa09cb91a2323ca51b";
const PYPI_URL = `https://raw.githubusercontent.com/hugovk/top-pypi-packages/${PYPI_COMMIT}/top-pypi-packages.min.json`;

const COUNT = 5000;
const DATA = fileURLToPath(new URL("../data/", import.meta.url));

async function download(url: string): Promise<Buffer> {
  const res = await fetch(url, { headers: { "user-agent": "vigil-data-fetch" } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

const sha256 = (b: Buffer) => createHash("sha256").update(b).digest("hex");

async function previousSources(): Promise<Record<string, { sha256?: string; version?: string }>> {
  try {
    return JSON.parse(await readFile(join(DATA, "SOURCES.json"), "utf8")) as Record<string, { sha256?: string; version?: string }>;
  } catch {
    return {};
  }
}

async function npmNames(): Promise<{ names: string[]; sha256: string }> {
  const bytes = await download(NPM_TARBALL);
  const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
  if (integrity !== NPM_HIGH_IMPACT_INTEGRITY) {
    throw new Error(`npm-high-impact integrity mismatch: expected ${NPM_HIGH_IMPACT_INTEGRITY}, got ${integrity}`);
  }
  const work = await mkdtemp(join(tmpdir(), "vigil-popular-"));
  try {
    const tgz = join(work, "t.tgz");
    await writeFile(tgz, bytes, { mode: 0o600 });
    const res = await run("tar", ["-xzf", tgz, "-C", work, "--", "package/lib/top.js"]);
    if (res.code !== 0) throw new Error(`extracting tarball: ${res.stderr}`);
    // The module is `export const top = ['a', 'b', ...]`: read the quoted strings, never evaluate it.
    const src = await readFile(join(work, "package/lib/top.js"), "utf8");
    const names = [...src.matchAll(/^\s*'([^'\n]+)',?\s*$/gm)].map((m) => m[1] as string);
    return { names, sha256: sha256(bytes) };
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

async function pypiNames(prev: { sha256?: string }): Promise<{ names: string[]; sha256: string; lastUpdate: string }> {
  const bytes = await download(PYPI_URL);
  const digest = sha256(bytes);
  if (prev.sha256 && prev.sha256 !== digest) {
    throw new Error(`top-pypi-packages at ${PYPI_COMMIT} changed: expected ${prev.sha256}, got ${digest}`);
  }
  const json = JSON.parse(bytes.toString("utf8")) as { last_update?: string; rows: { project: string }[] };
  return { names: json.rows.map((r) => r.project), sha256: digest, lastUpdate: json.last_update ?? "" };
}

function unique(names: string[]): string[] {
  return [...new Set(names)].slice(0, COUNT);
}

async function main(): Promise<void> {
  const prev = await previousSources();
  const npm = await npmNames();
  const pypi = await pypiNames(prev["popular-pypi"]?.version === PYPI_COMMIT ? (prev["popular-pypi"] ?? {}) : {});
  const npmList = unique(npm.names);
  // Store PyPI names PEP 503-normalized, as the matcher compares them.
  const pypiList = unique(pypi.names.map((n) => n.toLowerCase().replace(/[-_.]+/g, "-")));
  if (npmList.length < 1000 || pypiList.length < 1000) throw new Error("source format changed: too few names parsed");

  const fetched = new Date().toISOString().slice(0, 10);
  // Plain text, one name per line. In a JSON array, gitleaks' generic-api-key rule reads
  // `"fastapi-cache2", "next-name"` as an api keyword, an assignment (the comma) and a value.
  await writeFile(join(DATA, "popular-npm.txt"), npmList.join("\n") + "\n");
  await writeFile(join(DATA, "popular-pypi.txt"), pypiList.join("\n") + "\n");
  const sources = {
    "popular-npm": {
      source: "npm-high-impact (top list, first 5000 in order)",
      url: NPM_TARBALL,
      version: NPM_HIGH_IMPACT_VERSION,
      integrity: NPM_HIGH_IMPACT_INTEGRITY,
      sha256: npm.sha256,
      fetched,
      count: npmList.length,
    },
    "popular-pypi": {
      source: "hugovk/top-pypi-packages (30-day downloads, first 5000; names PEP 503-normalized)",
      url: PYPI_URL,
      version: PYPI_COMMIT,
      sha256: pypi.sha256,
      upstreamLastUpdate: pypi.lastUpdate,
      fetched,
      count: pypiList.length,
    },
  };
  await writeFile(join(DATA, "SOURCES.json"), JSON.stringify(sources, null, 2) + "\n");
  process.stdout.write(`popular-npm: ${npmList.length}, popular-pypi: ${pypiList.length}\n`);
}

main().catch((e: unknown) => {
  process.stderr.write(`fetch-popular: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(1);
});
