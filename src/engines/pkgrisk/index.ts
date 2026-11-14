/**
 * pkgrisk: supply-chain checks on declared dependencies (npm, PyPI). No binary.
 * Offline rules: typosquat, install-script. Network rules (registry lookups): nonexistent,
 * new-package, new-version, sdist-only. See docs/specs/package-risk.md.
 */
import { join } from "node:path";
import { fingerprint, type Finding, type Severity } from "../../core/finding.js";
import { cacheRoot } from "../install.js";
import type { EngineOutput } from "../types.js";
import { loadRefs, type Ecosystem, type PkgRef } from "./manifests.js";
import { isValidName, Registry, type FetchLike, type RegistryRecord } from "./registry.js";
import { isAllowed, loadTyposquatData } from "./typosquat.js";

export interface PkgriskOptions {
  /** Skip every registry lookup. */
  offline?: boolean;
  /** Test/bench hook: replaces the global fetch so nothing touches the network. */
  fetch?: FetchLike;
  /** Test/bench hook: the clock. */
  now?: () => number;
  /**
   * Where registry responses are cached. Absent: the Vigil cache dir (never the scanned repo).
   * Present but `undefined`: no cache (tests and the bench must not read or write the user's cache).
   */
  cacheDir?: string;
  sleep?: (ms: number) => Promise<void>;
}

const HOUR = 3_600_000;
const NEW_PACKAGE_MS = 30 * 24 * HOUR;
const NEW_VERSION_MS = 72 * HOUR;
const CONCURRENCY = 8;
/** Give up on the registry after this many consecutive failures. */
const MAX_CONSECUTIVE_FAILURES = 8;

const REGISTRY_LABEL: Record<Ecosystem, string> = { npm: "npm", PyPI: "PyPI" };

interface RuleInfo {
  severity: Severity;
  confidence: "high" | "medium" | "low";
  cwe: string;
}

const RULES: Record<string, RuleInfo> = {
  "pkg-nonexistent": { severity: "critical", confidence: "high", cwe: "CWE-829" },
  "pkg-typosquat": { severity: "high", confidence: "medium", cwe: "CWE-1357" },
  "pkg-new-package": { severity: "high", confidence: "medium", cwe: "CWE-1357" },
  "pkg-new-version": { severity: "medium", confidence: "low", cwe: "CWE-1357" },
  "pkg-install-script": { severity: "medium", confidence: "low", cwe: "CWE-829" },
  "pkg-sdist-only": { severity: "medium", confidence: "low", cwe: "CWE-829" },
};

const OWASP = "A08:2021 - Software and Data Integrity Failures";

async function pool<T>(items: T[], size: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(size, items.length) }, async () => {
      while (next < items.length) await fn(items[next++] as T);
    }),
  );
}

const key = (eco: Ecosystem, name: string) => `${eco}\u0000${name}`;

function ageText(ms: number): string {
  const hours = ms / HOUR;
  return hours < 48 ? `${Math.max(0, Math.floor(hours))} hours` : `${Math.floor(hours / 24)} days`;
}

export async function runPkgrisk(root: string, ignores: string[], opts: PkgriskOptions = {}): Promise<EngineOutput> {
  const { refs, notes } = await loadRefs(root, ignores);
  return assessRefs(refs, notes.map((n) => `pkgrisk: ${n}`), opts);
}

/** Run every pkgrisk rule over already-loaded package references (also used by the MCP `check_package` tool). */
export async function assessRefs(allRefs: PkgRef[], initialWarnings: string[], opts: PkgriskOptions = {}): Promise<EngineOutput> {
  const now = (opts.now ?? Date.now)();
  const warnings = [...initialWarnings];
  const data = loadTyposquatData();
  const popular = (r: PkgRef) => data[r.ecosystem].has(r.name);

  // Direct references first, package.json before lockfiles: the first one per package wins as the location.
  const refs = [...allRefs].sort((a, b) => Number(b.direct) - Number(a.direct) || a.file.localeCompare(b.file));

  const findings = new Map<string, Finding>();
  const flagged = new Set<string>(); // packages with a signal other than install-script
  const mk = (ruleId: string, r: PkgRef, title: string, message: string, version?: string): void => {
    const info = RULES[ruleId] as RuleInfo;
    const id = fingerprint("pkgrisk", ruleId, r.ecosystem, r.name, ...(ruleId === "pkg-new-version" ? [version ?? ""] : []));
    if (findings.has(id)) return;
    findings.set(id, {
      id,
      category: "dependency",
      engine: "pkgrisk",
      ruleId,
      title,
      message,
      severity: info.severity,
      confidence: info.confidence,
      location: { path: r.file, startLine: r.line },
      cwe: [info.cwe],
      owasp: [OWASP],
      dependency: { name: r.name, version: version ?? r.version ?? "", ecosystem: r.ecosystem, advisories: [], fixedVersions: [] },
    });
    if (ruleId !== "pkg-install-script" && ruleId !== "pkg-sdist-only") flagged.add(key(r.ecosystem, r.name));
  };

  // ---- offline: typosquat candidates (emitted below) ----
  const typos: { r: PkgRef; target: string }[] = [];
  for (const r of refs) {
    if (r.private || isAllowed(data, r.ecosystem, r.name)) continue;
    const m = data[r.ecosystem].match(r.name);
    if (m) typos.push({ r, target: m.target });
  }

  // ---- network: registry lookups ----
  const records = new Map<string, RegistryRecord>();
  const privateExists: string[] = [];
  const sdist: { r: PkgRef; version: string }[] = [];
  if (!opts.offline) {
    const registry = new Registry({ fetch: opts.fetch, now: opts.now, sleep: opts.sleep, cacheDir: "cacheDir" in opts ? opts.cacheDir : join(cacheRoot(), "pkgrisk") });
    // Look up direct deps and non-popular transitive deps. Popular transitive packages are skipped: they are
    // many, their documents are large, and a hijacked version of one is what osv's MAL- advisories cover.
    const targets = new Map<string, PkgRef>();
    for (const r of refs) {
      if (!isValidName(r.ecosystem, r.name)) continue;
      if (r.private && !r.direct) continue;
      if (!r.direct && popular(r)) continue;
      if (!targets.has(key(r.ecosystem, r.name))) targets.set(key(r.ecosystem, r.name), r);
    }
    let failures = 0;
    let consecutive = 0;
    let skipped = 0;
    await pool([...targets.entries()], CONCURRENCY, async ([k, r]) => {
      if (consecutive >= MAX_CONSECUTIVE_FAILURES) {
        skipped++;
        return;
      }
      const res = await registry.lookup(r.ecosystem, r.name);
      if (res.record) {
        consecutive = 0;
        if (r.private) {
          // Dependency-confusion setup: a private name that is also public.
          if (res.record.status === 200) privateExists.push(`${r.name} (${r.ecosystem}, ${r.file})`);
        } else records.set(k, res.record);
      } else {
        failures++;
        consecutive++;
      }
    });
    if (failures + skipped > 0) warnings.push(`pkgrisk: registry unreachable, ${failures + skipped} packages not checked`);
    for (const p of privateExists.sort()) {
      warnings.push(`pkgrisk: private package ${p} also exists on the public registry: dependency-confusion risk, make sure installs cannot fall back to it`);
    }

    for (const r of refs) {
      if (r.private) continue;
      const rec = records.get(key(r.ecosystem, r.name));
      if (!rec) continue;
      const where = REGISTRY_LABEL[r.ecosystem];
      if (rec.status === 404) {
        if (r.direct) {
          mk(
            "pkg-nonexistent",
            r,
            `Package does not exist: ${r.name}`,
            `\`${r.name}\` is declared as a dependency but does not exist on ${where}. AI assistants often invent package names, and an attacker can register such a name and ship malware to everyone who installs it. ` +
              `Check the spelling, or remove the dependency. Do not install it until you have confirmed the right package.`,
          );
        }
        continue;
      }
      const created = rec.created ? Date.parse(rec.created) : Number.NaN;
      if (!Number.isNaN(created) && now - created < NEW_PACKAGE_MS) {
        mk(
          "pkg-new-package",
          r,
          `Brand-new package: ${r.name}`,
          `\`${r.name}\` was first published on ${where} ${ageText(now - created)} ago. Most malicious packages are caught and removed within days, so very young packages deserve scrutiny. ` +
            `Verify the publisher and the source repository before installing.`,
        );
      }
      const pinned = r.version !== undefined;
      // npm: the lockfile's version only (package.json holds a range). PyPI: the pin, else what pip would pick.
      const version = r.version ?? (r.ecosystem === "PyPI" ? rec.latest : undefined);
      if (!version) continue;
      const published = rec.times?.[version] ? Date.parse(rec.times[version] as string) : Number.NaN;
      // An unpinned popular package is expected to release often (boto3 ships daily): flagging "latest" would be noise.
      if (!Number.isNaN(published) && now - published < NEW_VERSION_MS && (pinned || !popular(r))) {
        mk(
          "pkg-new-version",
          r,
          `Version published ${ageText(now - published)} ago: ${r.name}@${version}`,
          `\`${r.name}@${version}\` was published on ${where} ${ageText(now - published)} ago. Hijacked releases are usually found and pulled within days. ` +
            `Pin to a version older than 72 hours until it has had time to be reviewed.`,
          version,
        );
      }
      if (r.ecosystem === "PyPI" && rec.sdistOnly?.includes(version)) sdist.push({ r, version });
    }
  }

  // ---- typosquats (same result online and offline) ----
  for (const { r, target } of typos) {
    mk(
      "pkg-typosquat",
      r,
      `Possible typosquat: ${r.name}`,
      `\`${r.name}\` (${r.ecosystem}) is not a popular package, but its name is very close to the popular \`${target}\`. ` +
        `Typosquats copy a well-known name to get installed by mistake and usually carry malware. ` +
        `Check the spelling: did you mean \`${target}\`? If \`${r.name}\` is really what you want, verify its publisher before installing.`,
    );
  }

  // ---- install scripts / sdist-only: reported alone only for direct deps outside the popular list ----
  const counts = { install: new Set<string>(), sdist: new Set<string>() };
  for (const r of refs) {
    if (r.private || !r.installScript) continue;
    const k = key(r.ecosystem, r.name);
    if (flagged.has(k) || (r.direct && !popular(r))) {
      mk(
        "pkg-install-script",
        r,
        `Runs install-time code: ${r.name}`,
        `\`${r.name}\` runs a preinstall/install/postinstall script when installed. Install scripts run with your user's rights before you have looked at the code, which is how most npm malware executes. ` +
          `Verify the publisher before installing, or install with \`--ignore-scripts\` and review the script.`,
      );
    } else counts.install.add(k);
  }
  for (const { r, version } of sdist) {
    const k = key(r.ecosystem, r.name);
    if (flagged.has(k) || (r.direct && !popular(r))) {
      mk(
        "pkg-sdist-only",
        r,
        `No wheel published: ${r.name}`,
        `\`${r.name}@${version}\` has no prebuilt wheel, so pip runs its \`setup.py\` on your machine at install time. Build-time code runs before you have reviewed it. ` +
          `Verify the publisher before installing, or use \`--only-binary :all:\` where a wheel exists.`,
        version,
      );
    } else counts.sdist.add(k);
  }
  if (counts.install.size) warnings.push(`pkgrisk: ${counts.install.size} dependencies run install scripts (not reported individually)`);
  if (counts.sdist.size) warnings.push(`pkgrisk: ${counts.sdist.size} dependencies are sdist-only (not reported individually)`);

  return { findings: [...findings.values()], warnings };
}
