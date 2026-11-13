/**
 * Discover and parse dependency manifests (npm and PyPI). Pure parsers plus a small
 * discovery walk. Manifests belong to the (untrusted) scanned repo, so every parser
 * tolerates garbage and nothing here executes or follows anything from them.
 */
import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { isIgnored } from "../../core/ignore.js";

export type Ecosystem = "npm" | "PyPI";

export interface PkgRef {
  ecosystem: Ecosystem;
  /** npm: as written. PyPI: PEP 503 normalized. */
  name: string;
  /** Resolved version: lockfile version or a `==` pin. */
  version?: string;
  direct: boolean;
  /** Path relative to the scan root, forward slashes. */
  file: string;
  line: number;
  installScript?: boolean;
  /** Comes from a private scope/index/registry: never looked up on the public registry. */
  private?: boolean;
}

export const normalizePypi = (name: string): string => name.toLowerCase().replace(/[-_.]+/g, "-");

// ---- npm ------------------------------------------------------------------

const NPM_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies"] as const;

/** Version specs that do not point at the public registry. */
export function isRegistrySpec(spec: string): boolean {
  const s = spec.trim();
  if (/^(file|link|git|git\+[a-z]+|http|https|workspace|github|gitlab|bitbucket|gist|portal|patch):/i.test(s)) return false;
  if (/^[./~]/.test(s)) return false;
  // `user/repo` GitHub shorthand.
  if (/^[\w.-]+\/[\w.-]+(#.*)?$/.test(s)) return false;
  return true;
}

/** `npm:real@^1` aliases install `real` under another name. */
function resolveAlias(name: string, spec: string): string | undefined {
  const m = spec.trim().match(/^npm:(@[^/@]+\/[^@]+|[^@]+)(?:@.*)?$/);
  return m ? m[1] : name;
}

interface LineIndex {
  [key: string]: number;
}

/** Line numbers of `"name": ...` keys, per top-level section, for formatted JSON. */
function packageJsonLines(text: string): Record<string, LineIndex> {
  const out: Record<string, LineIndex> = {};
  let section: string | undefined;
  text.split("\n").forEach((raw, i) => {
    const open = raw.match(/^\s*"(dependencies|devDependencies|optionalDependencies)"\s*:\s*\{/);
    if (open) {
      section = open[1];
      out[section as string] ??= {};
      return;
    }
    if (!section) return;
    if (/^\s*\}/.test(raw)) {
      section = undefined;
      return;
    }
    const key = raw.match(/^\s*"((?:[^"\\]|\\.)+)"\s*:/);
    if (key?.[1]) (out[section] as LineIndex)[key[1]] ??= i + 1;
  });
  return out;
}

export function parsePackageJson(text: string, file: string): PkgRef[] {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return [];
  }
  if (typeof json !== "object" || json === null) return [];
  const lines = packageJsonLines(text);
  const refs: PkgRef[] = [];
  for (const section of NPM_SECTIONS) {
    const deps = (json as Record<string, unknown>)[section];
    if (typeof deps !== "object" || deps === null || Array.isArray(deps)) continue;
    for (const [key, spec] of Object.entries(deps)) {
      if (typeof spec !== "string" || !isRegistrySpec(spec)) continue;
      const name = resolveAlias(key, spec);
      if (!name) continue;
      refs.push({ ecosystem: "npm", name, direct: true, file, line: lines[section]?.[key] ?? 1 });
    }
  }
  return refs;
}

export interface LockParse {
  refs: PkgRef[];
  /** Names declared by the lockfile's root package. */
  rootDeps: Set<string>;
  /** lockfileVersion 1 has no `packages` map: nothing to check. */
  unsupported?: boolean;
}

const GIT_HOSTS = /(^|\.)(github\.com|githubusercontent\.com|gitlab\.com|bitbucket\.org)$/i;
const PUBLIC_NPM_HOSTS = new Set(["registry.npmjs.org", "registry.yarnpkg.com"]);

export function parsePackageLock(text: string, file: string): LockParse {
  const empty: LockParse = { refs: [], rootDeps: new Set() };
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return empty;
  }
  const packages = (json as { packages?: unknown } | null)?.packages;
  if (typeof packages !== "object" || packages === null) return { ...empty, unsupported: true };

  const lineOf = new Map<string, number>();
  text.split("\n").forEach((raw, i) => {
    const m = raw.match(/^\s*"((?:[^"\\]|\\.)*node_modules\/(?:[^"\\]|\\.)*)"\s*:\s*\{/);
    if (m?.[1] && !lineOf.has(m[1])) lineOf.set(m[1], i + 1);
  });

  const root = (packages as Record<string, Record<string, unknown> | undefined>)[""];
  const rootDeps = new Set<string>();
  for (const section of NPM_SECTIONS) {
    const deps = root?.[section];
    if (typeof deps === "object" && deps !== null) for (const n of Object.keys(deps)) rootDeps.add(n);
  }

  const byKey = new Map<string, PkgRef>();
  for (const [key, raw] of Object.entries(packages as Record<string, unknown>)) {
    if (!key.includes("node_modules/") || typeof raw !== "object" || raw === null) continue;
    const entry = raw as Record<string, unknown>;
    if (entry.link === true) continue;
    const resolved = typeof entry.resolved === "string" ? entry.resolved : undefined;
    let isPrivate = false;
    if (resolved) {
      if (!/^https?:/i.test(resolved)) continue; // git, file: not a registry package
      let host: string;
      try {
        host = new URL(resolved).hostname;
      } catch {
        continue;
      }
      // Tarballs straight from a git host are git dependencies, not registry packages.
      if (GIT_HOSTS.test(host)) continue;
      isPrivate = !PUBLIC_NPM_HOSTS.has(host);
    }
    const installed = key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
    const name = typeof entry.name === "string" ? entry.name : installed;
    const version = typeof entry.version === "string" ? entry.version : undefined;
    const topLevel = key === `node_modules/${installed}`;
    const ref: PkgRef = {
      ecosystem: "npm",
      name,
      version,
      direct: topLevel && rootDeps.has(installed),
      file,
      line: lineOf.get(key) ?? 1,
      installScript: entry.hasInstallScript === true,
      private: isPrivate || undefined,
    };
    const id = `${name}@${version ?? ""}`;
    const prev = byKey.get(id);
    if (!prev) byKey.set(id, ref);
    else {
      prev.direct ||= ref.direct;
      prev.installScript ||= ref.installScript;
    }
  }
  return { refs: [...byKey.values()], rootDeps };
}

export interface Npmrc {
  scopes: Set<string>;
  /** `registry=` points somewhere other than the public registry. */
  customRegistry: boolean;
}

export function parseNpmrc(text: string): Npmrc {
  const out: Npmrc = { scopes: new Set(), customRegistry: false };
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const scoped = line.match(/^(@[^:=\s]+):registry\s*=/);
    if (scoped?.[1]) {
      out.scopes.add(scoped[1].toLowerCase());
      continue;
    }
    const reg = line.match(/^registry\s*=\s*(\S+)/);
    if (reg?.[1]) {
      try {
        if (!PUBLIC_NPM_HOSTS.has(new URL(reg[1]).hostname)) out.customRegistry = true;
      } catch {
        out.customRegistry = true;
      }
    }
  }
  return out;
}

// ---- PyPI -----------------------------------------------------------------

/** Parse one PEP 508 requirement string. Returns undefined for anything that is not a plain registry requirement. */
export function parseRequirement(raw: string): { name: string; version?: string } | undefined {
  let s = raw.trim();
  if (!s || s.startsWith("-") || s.startsWith("#")) return undefined;
  s = s.split(/\s+--/)[0] ?? s; // per-requirement options such as --hash=...
  s = s.split(";")[0] ?? s; // environment markers
  s = s.replace(/\s+#.*$/, "").trim();
  if (/^(https?|file|git\+[a-z]+|git|ssh):/i.test(s) || /^[./~]/.test(s) || s.includes("://")) return undefined;
  const m = s.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/);
  if (!m?.[1]) return undefined;
  const rest = (m[3] ?? "").trim();
  if (rest.startsWith("@")) return undefined; // `name @ url` direct reference
  const pin = rest.match(/(?:^|,)\s*===?\s*([A-Za-z0-9][A-Za-z0-9._!+-]*)\s*(?:,|$)/);
  const version = pin?.[1] && !pin[1].includes("*") ? pin[1] : undefined;
  return { name: normalizePypi(m[1]), version };
}

export interface RequirementsParse {
  refs: PkgRef[];
  /** The file names a non-default package index: its requirements are not public. */
  privateIndex: boolean;
}

function isPublicIndex(url: string): boolean {
  try {
    const h = new URL(url).hostname;
    return h === "pypi.org" || h === "pypi.python.org" || h === "files.pythonhosted.org";
  } catch {
    return false;
  }
}

export function parseRequirements(text: string, file: string): RequirementsParse {
  const refs: PkgRef[] = [];
  let privateIndex = false;
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const startLine = i + 1;
    let line = (lines[i] ?? "").replace(/\r$/, "");
    while (line.endsWith("\\") && i + 1 < lines.length) {
      i++;
      line = line.slice(0, -1) + " " + (lines[i] ?? "").replace(/\r$/, "");
    }
    line = line.replace(/(^|\s)#.*$/, "").trim();
    if (!line) continue;
    const idx = line.match(/^(?:--index-url|--extra-index-url|-i)(?:\s+|=)(\S+)/);
    if (idx?.[1]) {
      if (!isPublicIndex(idx[1])) privateIndex = true;
      continue;
    }
    if (line.startsWith("-")) continue; // -r, -c, -e, --find-links, ...
    const req = parseRequirement(line);
    if (req) refs.push({ ecosystem: "PyPI", name: req.name, version: req.version, direct: true, file, line: startLine });
  }
  if (privateIndex) for (const r of refs) r.private = true;
  return { refs, privateIndex };
}

/** Reads only `dependencies = [ ... ]` under `[project]`. Multi-line, quotes and comments handled. */
export function parsePyproject(text: string, file: string): PkgRef[] {
  const refs: PkgRef[] = [];
  const lines = text.split("\n");
  let inProject = false;
  let depth = 0; // > 0 while inside the dependencies array
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    if (depth === 0) {
      const header = raw.match(/^\s*\[\[?([^\]]+)\]\]?\s*(?:#.*)?$/);
      if (header) {
        inProject = header[1]?.trim() === "project";
        continue;
      }
      if (!inProject) continue;
      const start = raw.match(/^\s*dependencies\s*=\s*\[/);
      if (!start) continue;
    }
    // Scan the line, honoring quotes; stop at a comment.
    let j = depth === 0 ? raw.indexOf("[") : 0;
    if (depth === 0) {
      depth = 1;
      j++;
    }
    let quote: string | undefined;
    let buf = "";
    for (; j < raw.length; j++) {
      const ch = raw[j] as string;
      if (quote) {
        if (ch === "\\" && quote === '"') {
          buf += raw[++j] ?? "";
        } else if (ch === quote) {
          const req = parseRequirement(buf);
          if (req) refs.push({ ecosystem: "PyPI", name: req.name, version: req.version, direct: true, file, line: i + 1 });
          quote = undefined;
          buf = "";
        } else buf += ch;
        continue;
      }
      if (ch === '"' || ch === "'") quote = ch;
      else if (ch === "#") break;
      else if (ch === "]") {
        depth = 0;
        inProject = false;
        break;
      }
    }
  }
  return refs;
}

// ---- discovery ------------------------------------------------------------

/** Lockfiles pkgrisk does not read in v1. */
const UNSUPPORTED = new Set(["yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile", "Pipfile.lock", "uv.lock"]);
const REQUIREMENTS = /^requirements.*\.txt$/;

export interface Discovered {
  files: string[];
  unsupported: string[];
}

export async function discoverManifests(root: string, ignores: string[]): Promise<Discovered> {
  const files: string[] = [];
  const unsupported: string[] = [];
  async function walk(rel: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(join(root, rel), { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const path = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (!isIgnored(`${path}/`, ignores) && !isIgnored(path, ignores)) await walk(path);
      } else if (e.isFile() && !isIgnored(path, ignores)) {
        if (UNSUPPORTED.has(e.name)) unsupported.push(path);
        else if (e.name === "package.json" || e.name === "package-lock.json" || e.name === "pyproject.toml" || REQUIREMENTS.test(e.name)) files.push(path);
      }
    }
  }
  await walk("");
  return { files, unsupported };
}

export interface LoadedRefs {
  refs: PkgRef[];
  notes: string[];
}

async function readText(root: string, rel: string): Promise<string | undefined> {
  try {
    return await readFile(join(root, rel), "utf8");
  } catch {
    return undefined;
  }
}

/** .npmrc files from the manifest's directory up to the scan root. */
async function npmrcFor(root: string, dir: string, cache: Map<string, Npmrc | undefined>): Promise<Npmrc[]> {
  const out: Npmrc[] = [];
  for (let d = dir; ; d = dirname(d)) {
    const key = d === "." ? "" : d;
    if (!cache.has(key)) {
      const text = await readText(root, key ? `${key}/.npmrc` : ".npmrc");
      cache.set(key, text === undefined ? undefined : parseNpmrc(text));
    }
    const rc = cache.get(key);
    if (rc) out.push(rc);
    if (d === "." || d === "" || d === "/") break;
  }
  return out;
}

const dirOf = (file: string): string => (file.includes("/") ? file.slice(0, file.lastIndexOf("/")) : ".");

export async function loadRefs(root: string, ignores: string[]): Promise<LoadedRefs> {
  const { files, unsupported } = await discoverManifests(root, ignores);
  const notes: string[] = [];
  const refs: PkgRef[] = [];
  const rcCache = new Map<string, Npmrc | undefined>();
  const byDir = new Map<string, { pj?: string; lock?: string }>();
  for (const f of files) {
    const base = f.slice(f.lastIndexOf("/") + 1);
    if (base === "package.json" || base === "package-lock.json") {
      const d = dirOf(f);
      const slot = byDir.get(d) ?? {};
      if (base === "package.json") slot.pj = f;
      else slot.lock = f;
      byDir.set(d, slot);
    } else if (base === "pyproject.toml") {
      const text = await readText(root, f);
      if (text !== undefined) refs.push(...parsePyproject(text, f));
    } else {
      const text = await readText(root, f);
      if (text !== undefined) refs.push(...parseRequirements(text, f).refs);
    }
  }

  for (const [dir, { pj, lock }] of byDir) {
    const rcs = await npmrcFor(root, dir, rcCache);
    const scopes = new Set(rcs.flatMap((r) => [...r.scopes]));
    const custom = rcs.some((r) => r.customRegistry);
    const markPrivate = (r: PkgRef) => {
      if (custom || (r.name.startsWith("@") && scopes.has(r.name.slice(0, r.name.indexOf("/")).toLowerCase()))) r.private = true;
    };

    const pjRefs = pj ? parsePackageJson((await readText(root, pj)) ?? "", pj) : [];
    const lockParse = lock ? parsePackageLock((await readText(root, lock)) ?? "", lock) : undefined;
    if (lockParse?.unsupported) notes.push(`${lock}: lockfileVersion 1 not checked by pkgrisk`);
    const lockRefs = lockParse?.refs ?? [];
    const lockByName = new Map(lockRefs.filter((r) => r.direct).map((r) => [r.name, r]));
    const declared = new Set<string>();
    // Direct dependencies are located in package.json and carry the lockfile's resolved data.
    for (const d of pjRefs) {
      declared.add(d.name);
      const l = lockByName.get(d.name);
      refs.push({ ...d, version: l?.version, installScript: l?.installScript, private: l?.private });
    }
    for (const l of lockRefs) {
      if (l.direct && declared.has(l.name)) continue;
      refs.push(l);
    }
    for (const r of refs) if (r.ecosystem === "npm" && (r.file === pj || r.file === lock)) markPrivate(r);
  }
  for (const u of unsupported) notes.push(`${u}: not checked by pkgrisk`);
  return { refs, notes };
}
