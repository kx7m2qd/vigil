/**
 * Import-level reachability for vulnerable npm and PyPI dependencies.
 *
 * For each osv-scanner finding, look at the project the lockfile belongs to (its directory and
 * everything under it) and decide:
 *   reachable   - the package, or a package that pulls it in, is imported in source or named in
 *                 tooling (scripts, Dockerfile, CI, config) or as a string
 *   unreachable - the lockfile's dependency graph shows it is only pulled in by the project's own
 *                 production dependencies, and neither it nor anything on those paths is used
 *   unknown     - we can't tell: no readable dependency graph, dev tooling, dynamic imports, a
 *                 library that loads it by name at runtime, or a partial view of the project
 *
 * Every rule here leans towards "reachable"/"unknown": a wrong "unreachable" hides real risk.
 * Runs entirely locally; it reads files, never executes them (Python is only *parsed*, see pyast.ts).
 */
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { SEVERITY_ORDER, type Finding, type Reachability } from "../core/finding.js";
import { isIgnored } from "../core/ignore.js";
import { normalizePypi, parseRequirements } from "../engines/pkgrisk/manifests.js";
import {
  keysFor,
  npmLockGraph,
  pipCompileGraph,
  poetryDeclared,
  poetryLockGraph,
  uvLockGraph,
  yarnLockGraph,
  bunLockGraph,
  stripJsonc,
  type DeclaredDeps,
  type DepGraph,
} from "./graph.js";
import { npmLoaders, pypiLoaders } from "./implicit.js";
import { findToken, jsImports, npmPackageOf, pyImports, type FileImports } from "./imports.js";
import { pythonAstImports } from "./pyast.js";
import { exactModules, moduleCandidates } from "./pypi-modules.js";

type Where = { path: string; line: number };
type Use = Where & { how: "imported" | "named" | "referenced" };

const JS_SOURCE = /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/;
const PY_SOURCE = /\.py$/;
const TOOLING =
  /^(?:Dockerfile.*|Containerfile|Procfile|Makefile|Justfile|package\.json|pyproject\.toml|setup\.cfg|tox\.ini|pytest\.ini|\.pre-commit-config\.ya?ml|.*\.(?:sh|bash|ya?ml|toml|ini|cfg|conf)|\.[\w-]+rc(?:\.(?:json|ya?ml|[cm]?js))?|.*\.config\.[cm]?[jt]s)$/;
const NOT_TOOLING = /^(?:pnpm-lock\.yaml|yarn\.lock|bun\.lock|poetry\.lock|uv\.lock|Pipfile\.lock)$/;
const REQUIREMENTS = /^requirements.*\.txt$|^(?:dev|test)-requirements.*\.txt$/;
/** Requirements files for tooling, not the running app. */
const DEV_REQUIREMENTS = /^requirements[-_.]?(?:dev|test|tests|lint|docs|ci|build)\b.*\.txt$|^(?:dev|test)-requirements.*\.txt$/;
/** Quoted strings that could name an npm package (`'pg'`, `"@scope/x/sub"`). */
const JS_STRING = /(['"`])((?:@[\w.-]+\/)?[\w.-]+(?:\/[\w./-]*)?)\1/g;
/** Command words that run the package manager on the machine, not a copy installed as a dependency. */
const PACKAGE_MANAGERS = new Set(["npm", "npx", "yarn", "pnpm", "corepack"]);
/**
 * Free-text tokens worth looking for in tooling. A package the project declares counts by any of
 * them; for anything else, very short names (`d`, `i`) match ordinary words and package-manager
 * names match the system tool, so those are dropped.
 */
const toolingTokens = (tokens: string[], declared: boolean) =>
  declared ? tokens : tokens.filter((t) => t.replace(/^-m /, "").length >= 3 && !PACKAGE_MANAGERS.has(t));
const MAX_FILE_BYTES = 1_000_000;
const MAX_FILES = 20_000;
const MAX_ANCESTORS = 5_000;

interface Project {
  dir: string;
  /** npm package / Python top-level module → first import seen. Python keys are lowercase. */
  js: Map<string, Where>;
  py: Map<string, Where>;
  /** Quoted names in source: `client: 'pg'`, Django INSTALLED_APPS, Celery config, ... */
  jsStrings: Map<string, Where>;
  pyStrings: Map<string, Where>;
  jsDynamic?: Where;
  pyDynamic?: Where;
  tooling: { path: string; text: string }[];
  /** False if the walk hit MAX_FILES: no "unreachable" verdicts from a partial view. */
  complete: boolean;
  /** Manifests and lockfiles in the project directory itself, by file name. */
  manifests: Map<string, string>;
  npmDeclared?: DeclaredDeps;
  bins: Map<string, string[]>;
  graphs: Map<string, DepGraph | undefined>;
  uses: Map<string, Use | undefined>;
}

const dirOf = (file: string): string => (file.includes("/") ? file.slice(0, file.lastIndexOf("/")) : "");
const baseOf = (file: string): string => file.slice(file.lastIndexOf("/") + 1);
const lineAt = (text: string, index: number) => text.slice(0, index).split("\n").length;

async function readSmall(root: string, rel: string): Promise<string | undefined> {
  try {
    const p = join(root, rel);
    if ((await stat(p)).size > MAX_FILE_BYTES * 20) return undefined; // lockfiles can be large
    const text = await readFile(p, "utf8");
    return text;
  } catch {
    return undefined;
  }
}

async function listFiles(root: string, dir: string, ignores: string[]): Promise<{ files: string[]; complete: boolean }> {
  const files: string[] = [];
  let complete = true;
  async function walk(rel: string): Promise<void> {
    if (files.length >= MAX_FILES) return void (complete = false);
    let entries;
    try {
      entries = await readdir(join(root, rel), { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const path = rel ? `${rel}/${e.name}` : e.name;
      // Symlinks are skipped (isDirectory/isFile are false for them): they can point outside the repo.
      if (e.isDirectory()) {
        if (!isIgnored(`${path}/`, ignores) && !isIgnored(path, ignores)) await walk(path);
      } else if (e.isFile() && !isIgnored(path, ignores)) {
        if (files.length >= MAX_FILES) return void (complete = false);
        files.push(path);
      }
    }
  }
  await walk(dir);
  return { files, complete };
}

function npmDeclared(text: string | undefined): DeclaredDeps | undefined {
  if (text === undefined) return undefined;
  try {
    const pj = JSON.parse(text) as Record<string, Record<string, string> | undefined>;
    const entries = (...ks: string[]) => new Map(ks.flatMap((k) => Object.entries(pj[k] ?? {})));
    return { prod: entries("dependencies", "optionalDependencies", "peerDependencies"), dev: entries("devDependencies") };
  } catch {
    return undefined;
  }
}

function lockBins(lock: string | undefined): Map<string, string[]> {
  const bins = new Map<string, string[]>();
  try {
    const packages = (JSON.parse(lock ?? "{}") as { packages?: Record<string, { bin?: Record<string, string> | string }> }).packages ?? {};
    for (const [key, v] of Object.entries(packages)) {
      if (!key.includes("node_modules/") || !v.bin) continue;
      const name = key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
      const names = typeof v.bin === "string" ? [name.replace(/^@[^/]+\//, "")] : Object.keys(v.bin);
      bins.set(name, [...(bins.get(name) ?? []), ...names]);
    }
  } catch {
    // No or unreadable lockfile: package names still match.
  }
  return bins;
}

/** Executable names from bun.lock: `"bin": { "tsc": "bin/tsc" }` in each package's info object. */
function bunBins(lock: string | undefined): Map<string, string[]> {
  const bins = new Map<string, string[]>();
  if (!lock) return bins;
  try {
    const packages = (JSON.parse(stripJsonc(lock)) as { packages?: Record<string, unknown[]> }).packages ?? {};
    for (const entry of Object.values(packages)) {
      if (!Array.isArray(entry) || typeof entry[0] !== "string") continue;
      const at = entry[0].indexOf("@", 1);
      const name = at === -1 ? entry[0] : entry[0].slice(0, at);
      const obj = entry.find((e, i) => i > 0 && e && typeof e === "object" && !Array.isArray(e)) as { bin?: Record<string, string> | string } | undefined;
      if (!obj?.bin) continue;
      const names = typeof obj.bin === "string" ? [name.replace(/^@[^/]+\//, "")] : Object.keys(obj.bin);
      bins.set(name, [...new Set([...(bins.get(name) ?? []), ...names])]);
    }
  } catch {
    // Unreadable: package names still match.
  }
  return bins;
}

/**
 * Tooling text with prose removed, lines kept so line numbers stay right: comment lines (`#`, `//`,
 * block-comment lines), trailing ` # comments` in shell/YAML/TOML-style files, and YAML `name:` titles
 * (`- name: Prepare cypress artifacts` names a CI step; it doesn't run anything).
 */
export function scrubTooling(file: string, text: string): string {
  const base = baseOf(file);
  const hashComments = !/\.(?:[cm]?[jt]sx?|json)$|^\.[\w-]+rc$/.test(base) || /^\.(?:npmrc|yarnrc)$/.test(base);
  // JS configs, and rc files that are often JSON with comments (.jshintrc, .eslintrc).
  const slashComments = /\.(?:[cm]?[jt]sx?)$|^\.[\w-]+rc(?:\.json)?$/.test(base);
  const yaml = /\.ya?ml$/.test(base);
  return text
    .split("\n")
    .map((line) => {
      const t = line.trimStart();
      if (hashComments && t.startsWith("#")) return "";
      if (slashComments && (t.startsWith("//") || t.startsWith("/*") || t.startsWith("*"))) return "";
      if (yaml && /^(?:-\s+)?name:\s/.test(t)) return "";
      if (hashComments) return line.replace(/\s#\s.*$/, "");
      // ` // note` after code; `http://x` has no space before `//`.
      return slashComments ? line.replace(/\s\/\/\s.*$/, "") : line;
    })
    .join("\n");
}

/** package.json without its dependency lists, so a package being declared doesn't count as being used. */
function packageJsonTooling(text: string): string {
  try {
    const pj = JSON.parse(text) as Record<string, unknown>;
    for (const k of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta", "bundleDependencies", "bundledDependencies", "overrides", "resolutions", "name"]) delete pj[k];
    // Script names (`"email:dev"`) are labels; only the commands run anything.
    if (pj.scripts && typeof pj.scripts === "object") pj.scripts = Object.values(pj.scripts as Record<string, unknown>);
    return JSON.stringify(pj, null, 1);
  } catch {
    return "";
  }
}

/** pyproject.toml without its dependency declarations (lines kept, so line numbers stay right). */
function pyprojectTooling(text: string): string {
  let dropTable = false;
  let inProject = false;
  let depth = 0;
  return text
    .split("\n")
    .map((line) => {
      const h = /^\s*\[([^\]]+)\]\s*(?:#.*)?$/.exec(line);
      if (h && depth === 0) {
        const t = h[1]!.trim();
        inProject = t === "project";
        dropTable = /^tool\.poetry\.(?:dependencies|dev-dependencies|group\.[^.]+\.dependencies)$|^project\.optional-dependencies$|^dependency-groups$/.test(t);
        return line;
      }
      if (dropTable) return "";
      if (depth > 0 || (inProject && /^\s*dependencies\s*=\s*\[/.test(line))) {
        const bare = line.replace(/"[^"]*"|'[^']*'/g, "").replace(/#.*$/, "");
        depth += (bare.match(/\[/g) ?? []).length - (bare.match(/\]/g) ?? []).length;
        if (depth < 0) depth = 0;
        return "";
      }
      return line;
    })
    .join("\n");
}

async function analyze(root: string, dir: string, ignores: string[]): Promise<Project> {
  const { files, complete } = await listFiles(root, dir, ignores);
  const p: Project = {
    dir,
    js: new Map(),
    py: new Map(),
    jsStrings: new Map(),
    pyStrings: new Map(),
    tooling: [],
    complete,
    manifests: new Map(),
    bins: new Map(),
    graphs: new Map(),
    uses: new Map(),
  };
  const ast = await pythonAstImports(files.filter((f) => PY_SOURCE.test(f)).map((f) => join(root, f)));

  for (const path of files) {
    const base = baseOf(path);
    if (dirOf(path) === dir && (REQUIREMENTS.test(base) || /^(?:package\.json|package-lock\.json|yarn\.lock|bun\.lock|pyproject\.toml|poetry\.lock|uv\.lock)$/.test(base))) {
      const text = await readSmall(root, path);
      if (text !== undefined) p.manifests.set(base, text);
      if (REQUIREMENTS.test(base) || base.endsWith(".lock") || base === "package-lock.json") continue;
    }
    if (JS_SOURCE.test(base) && !/\.min\.js$/.test(base) && !base.endsWith(".d.ts")) {
      const text = await readSmallSource(root, path);
      if (text === undefined) continue;
      const r = jsImports(text);
      for (const h of r.imports) if (!p.js.has(h.name)) p.js.set(h.name, { path, line: h.line });
      if (r.dynamicLine !== undefined && !p.jsDynamic) p.jsDynamic = { path, line: r.dynamicLine };
      for (const m of text.matchAll(JS_STRING)) {
        const name = npmPackageOf(m[2] as string);
        if (name && !p.jsStrings.has(name)) p.jsStrings.set(name, { path, line: lineAt(text, m.index) });
      }
      // Config files (vite.config.ts, .eslintrc.cjs) also name plugins as strings.
      if (TOOLING.test(base)) p.tooling.push({ path, text: scrubTooling(path, text) });
      continue;
    }
    if (PY_SOURCE.test(base)) {
      const text = await readSmallSource(root, path);
      if (text === undefined) continue;
      const r: FileImports = ast.get(join(root, path)) ?? pyImports(text);
      for (const h of r.imports) {
        const k = h.name.toLowerCase();
        if (!p.py.has(k)) p.py.set(k, { path, line: h.line });
      }
      if (r.dynamicLine !== undefined && !p.pyDynamic) p.pyDynamic = { path, line: r.dynamicLine };
      for (const m of text.matchAll(/(['"])([A-Za-z_][\w.]*)\1/g)) {
        const k = (m[2] as string).split(".")[0]!.toLowerCase();
        if (!p.pyStrings.has(k)) p.pyStrings.set(k, { path, line: lineAt(text, m.index) });
      }
      continue;
    }
    if (TOOLING.test(base) && !NOT_TOOLING.test(base)) {
      let text = await readSmallSource(root, path);
      if (text === undefined) continue;
      if (base === "package.json") text = packageJsonTooling(text);
      if (base === "pyproject.toml") text = pyprojectTooling(text);
      p.tooling.push({ path, text: scrubTooling(path, text) });
    }
  }
  p.npmDeclared = npmDeclared(p.manifests.get("package.json"));
  p.bins = lockBins(p.manifests.get("package-lock.json"));
  for (const [k, v] of bunBins(p.manifests.get("bun.lock"))) p.bins.set(k, [...(p.bins.get(k) ?? []), ...v]);
  return p;
}

async function readSmallSource(root: string, rel: string): Promise<string | undefined> {
  try {
    const path = join(root, rel);
    if ((await stat(path)).size > MAX_FILE_BYTES) return undefined;
    return await readFile(path, "utf8");
  } catch {
    return undefined;
  }
}

// ---- dependency graphs -------------------------------------------------------

/** The graph for the lockfile a finding points at, falling back to the others in the directory. */
function graphFor(p: Project, ecosystem: "npm" | "PyPI", file: string): DepGraph | undefined {
  const key = `${ecosystem}:${file}`;
  if (p.graphs.has(key)) return p.graphs.get(key);
  const m = p.manifests;
  const npm: Record<string, () => DepGraph | undefined> = {
    "package-lock.json": () => (m.has("package-lock.json") ? npmLockGraph(m.get("package-lock.json")!, p.npmDeclared) : undefined),
    "yarn.lock": () => (m.has("yarn.lock") ? yarnLockGraph(m.get("yarn.lock")!, p.npmDeclared) : undefined),
    "bun.lock": () => (m.has("bun.lock") ? bunLockGraph(m.get("bun.lock")!) : undefined),
  };
  const reqs = () =>
    pipCompileGraph([...m.entries()].filter(([n]) => REQUIREMENTS.test(n)).map(([n, text]) => ({ text, dev: DEV_REQUIREMENTS.test(n) })));
  const pypi: Record<string, () => DepGraph | undefined> = {
    "uv.lock": () => (m.has("uv.lock") ? uvLockGraph(m.get("uv.lock")!) : undefined),
    "poetry.lock": () => (m.has("poetry.lock") ? poetryLockGraph(m.get("poetry.lock")!, m.get("pyproject.toml")) : undefined),
    requirements: reqs,
  };
  const table = ecosystem === "npm" ? npm : pypi;
  const own = table[REQUIREMENTS.test(file) ? "requirements" : file];
  // A finding from a different lockfile than the graph we can read would mix two different trees.
  const g = own ? own() : undefined;
  p.graphs.set(key, g);
  return g;
}

// ---- verdicts ----------------------------------------------------------------

interface Eco {
  /** How the project uses this package, if at all (imports, strings, tooling). */
  use(name: string): Use | undefined;
  loaders: Record<string, string[]>;
  dynamic?: Where;
  /** Declared in the manifest: used for messages when there is no graph. */
  declared: { prod: Set<string>; dev: Set<string> } | undefined;
  norm(name: string): string;
  noGraph: string;
}

function referenced(p: Project, tokens: string[]): Where | undefined {
  for (const t of p.tooling) {
    for (const tok of tokens) {
      const line = findToken(t.text, tok);
      if (line !== undefined) return { path: t.path, line: t.path.endsWith("package.json") ? 1 : line };
    }
  }
  return undefined;
}

function npmEco(p: Project, file: string): Eco {
  return {
    use(name) {
      const k = `npm:${name}`;
      if (p.uses.has(k)) return p.uses.get(k);
      const imp = p.js.get(name);
      // A quoted string in app code only means "loads this package" for packages the project declares
      // (`client: 'pg'`). Otherwise every short word in quotes would match some package (`"d"`, `"ms"`).
      const declared = !p.npmDeclared || p.npmDeclared.prod.has(name) || p.npmDeclared.dev.has(name);
      const str = declared ? p.jsStrings.get(name) : undefined;
      const ref = imp || str ? undefined : referenced(p, toolingTokens([name, ...(p.bins.get(name) ?? [])], declared));
      const u: Use | undefined = imp ? { ...imp, how: "imported" } : str ? { ...str, how: "named" } : ref ? { ...ref, how: "referenced" } : undefined;
      p.uses.set(k, u);
      return u;
    },
    loaders: npmLoaders(),
    dynamic: p.jsDynamic,
    declared: p.npmDeclared && { prod: new Set(p.npmDeclared.prod.keys()), dev: new Set(p.npmDeclared.dev.keys()) },
    norm: (n) => n,
    noGraph:
      file === "pnpm-lock.yaml"
        ? "Vigil can't read pnpm-lock.yaml's dependency graph yet"
        : `Vigil couldn't read a dependency graph from ${file}`,
  };
}

function pypiEco(p: Project, file: string): Eco {
  const reqFiles = [...p.manifests.entries()].filter(([n]) => REQUIREMENTS.test(n));
  const prod = new Set<string>();
  const dev = new Set<string>();
  for (const [n, text] of reqFiles) for (const r of parseRequirements(text, n).refs) (DEV_REQUIREMENTS.test(n) ? dev : prod).add(r.name);
  const pyproject = p.manifests.get("pyproject.toml");
  if (pyproject) {
    const d = poetryDeclared(pyproject);
    d.prod.forEach((n) => prod.add(n));
    d.dev.forEach((n) => dev.add(n));
  }
  // Packages the project asks for itself. pip-compile output pins everything, so when there is a graph
  // its roots say which ones are direct; a flat requirements file is taken at its word.
  const g = graphFor(p, "PyPI", file);
  const direct = g ? new Set([...g.roots, ...g.devRoots].map((k) => normalizePypi(g.nodes.get(k)?.name ?? k))) : new Set([...prod, ...dev]);
  return {
    use(raw) {
      const name = normalizePypi(raw);
      const k = `pypi:${name}`;
      if (p.uses.has(k)) return p.uses.get(k);
      const mods = moduleCandidates(name).map((m) => m.toLowerCase());
      let u: Use | undefined;
      for (const m of mods) {
        const imp = p.py.get(m);
        if (imp) {
          u = { ...imp, how: "imported" };
          break;
        }
      }
      // As for npm: quoted strings only count for declared packages (Django INSTALLED_APPS, Celery brokers).
      const declared = !direct.size || direct.has(name);
      if (!u && declared)
        for (const m of mods) {
          const s = p.pyStrings.get(m);
          if (s) {
            u = { ...s, how: "named" };
            break;
          }
        }
      if (!u) {
        // Free text only matches exact names; guessed module names (pytest → "test") count after `-m`.
        const exact = exactModules(name);
        const ref =
          referenced(p, toolingTokens([...new Set([raw, name, ...exact.map((m) => m.toLowerCase()), ...exact])], declared)) ??
          referenced(p, toolingTokens(moduleCandidates(name).map((m) => `-m ${m}`), declared));
        if (ref) u = { ...ref, how: "referenced" };
      }
      p.uses.set(k, u);
      return u;
    },
    loaders: pypiLoaders(),
    dynamic: p.pyDynamic,
    declared: prod.size || dev.size ? { prod, dev } : undefined,
    norm: normalizePypi,
    noGraph: REQUIREMENTS.test(file)
      ? `${file} doesn't record which packages depend on which (pip-compile, uv or Poetry lockfiles do)`
      : `Vigil couldn't read a dependency graph from ${file}`,
  };
}

const describeUse = (name: string, u: Use) =>
  u.how === "imported"
    ? `${name} is imported at ${u.path}:${u.line}`
    : u.how === "named"
      ? `${name} is named as a string at ${u.path}:${u.line}`
      : `${name} is referenced in ${u.path}:${u.line}`;

interface Walk {
  live?: { chain: string[]; use: Use };
  prodRoots: string[];
  devRoots: string[];
  orphan: boolean;
  names: Set<string>;
}

/** Walk up from the package to the project's own dependencies, stopping at the first one in use. */
function walkUp(g: DepGraph, start: string[], eco: Eco): Walk {
  const w: Walk = { prodRoots: [], devRoots: [], orphan: false, names: new Set() };
  const prev = new Map<string, string | undefined>(start.map((k) => [k, undefined]));
  const queue = [...start];
  while (queue.length) {
    const k = queue.shift()!;
    const n = g.nodes.get(k);
    if (!n) continue;
    w.names.add(n.name);
    const u = eco.use(n.name);
    if (u) {
      const chain: string[] = [];
      for (let c: string | undefined = k; c !== undefined; c = prev.get(c)) chain.push(g.nodes.get(c)?.name ?? c);
      w.live = { chain: chain.reverse(), use: u };
      return w;
    }
    if (g.roots.has(k)) w.prodRoots.push(n.name);
    if (g.devRoots.has(k)) w.devRoots.push(n.name);
    const parents = g.parents.get(k);
    if (!parents?.size && !g.roots.has(k) && !g.devRoots.has(k)) w.orphan = true;
    for (const par of parents ?? []) {
      if (prev.has(par)) continue;
      if (prev.size >= MAX_ANCESTORS) {
        w.orphan = true;
        break;
      }
      prev.set(par, k);
      queue.push(par);
    }
  }
  return w;
}

const list = (names: string[]) => {
  const u = [...new Set(names)];
  return u.length <= 3 ? u.join(", ") : `${u.slice(0, 3).join(", ")} and ${u.length - 3} more`;
};

function verdict(p: Project, eco: Eco, g: DepGraph | undefined, rawName: string, version: string | undefined): Reachability {
  const name = eco.norm(rawName);
  const direct = eco.use(name);
  if (direct) return { status: "reachable", reason: `${describeUse(rawName, direct)}.`, evidence: { path: direct.path, line: direct.line } };

  if (!g) {
    if (eco.declared?.dev.has(name) && !eco.declared.prod.has(name))
      return { status: "unknown", reason: `${rawName} is a dev dependency with no import found; dev tools are often run through CLIs or config Vigil can't fully trace.` };
    return { status: "unknown", reason: `No import of ${rawName} found, but ${eco.noGraph}, so Vigil can't tell whether a package the project uses depends on it.` };
  }
  const start = keysFor(g, name, version);
  if (!start.length) return { status: "unknown", reason: `${rawName} isn't in the lockfile's dependency graph, so Vigil can't trace what pulls it in.` };

  const w = walkUp(g, start, eco);
  if (w.live) {
    const [, ...rest] = w.live.chain;
    const via = rest.length > 1 ? ` (${w.live.chain.join(" ← ")})` : "";
    return {
      status: "reachable",
      reason: `${rawName} is pulled in by ${rest[rest.length - 1]}${via}; ${describeUse(rest[rest.length - 1]!, w.live.use)}.`,
      evidence: { path: w.live.use.path, line: w.live.use.line },
    };
  }
  if (w.devRoots.length)
    return { status: "unknown", reason: `${rawName} is pulled in by dev dependency ${list(w.devRoots)}; dev tools are often run through CLIs or config Vigil can't fully trace.` };
  if (w.orphan || !w.prodRoots.length)
    return { status: "unknown", reason: `Vigil couldn't trace every package that pulls in ${rawName} back to the project's own dependencies.` };
  for (const [loader, loads] of Object.entries(eco.loaders)) {
    if (![...w.names].some((n) => loads.includes(n))) continue;
    const lk = keysFor(g, loader);
    const used = eco.use(loader) ?? (lk.length ? walkUp(g, lk, eco).live?.use : undefined);
    if (used) return { status: "unknown", reason: `${rawName} isn't imported, but ${loader} (used at ${used.path}:${used.line}) can load it by name at runtime.`, evidence: { path: used.path, line: used.line } };
  }
  if (eco.dynamic) return { status: "unknown", reason: `No import of ${rawName} found, but the project loads modules dynamically.`, evidence: eco.dynamic };
  if (!p.complete) return { status: "unknown", reason: `No import of ${rawName} found, but the project was too large to read completely.` };
  const roots = w.prodRoots.filter((r) => r !== name);
  return {
    status: "unreachable",
    reason: roots.length
      ? `${rawName} is only pulled in by ${list(roots)}${w.prodRoots.includes(name) ? ` (and listed directly)` : ""}, and nothing in this project imports ${roots.length === 1 ? "that" : "those"} or names ${roots.length === 1 ? "it" : "them"} in scripts or config.`
      : `${rawName} is a direct dependency, but nothing in this project imports it or names it in scripts or config, and no package the project uses depends on it.`,
  };
}

/** Findings reachability applies to: known-vulnerable npm/PyPI versions. Malicious packages are excluded: their install scripts run whether or not anything imports them. */
export function isReachabilityCandidate(f: Finding): boolean {
  const eco = f.dependency?.ecosystem;
  return f.engine === "osv-scanner" && f.ruleId !== "pkg-known-malicious" && (eco === "npm" || eco === "PyPI");
}

/**
 * Annotate findings in place with `reachability`. Unreachable findings are lowered one severity
 * level (never hidden) and their message says so; `originalSeverity` keeps the old level, which
 * the CLI's --fail-on gate still uses unless --trust-reachability is passed.
 */
export async function applyReachability(root: string, findings: Finding[], ignores: string[]): Promise<void> {
  const projects = new Map<string, Promise<Project>>();
  for (const f of findings) {
    if (!isReachabilityCandidate(f) || !f.dependency) continue;
    const dir = dirOf(f.location.path);
    if (!projects.has(dir)) projects.set(dir, analyze(root, dir, ignores));
    const p = await projects.get(dir)!;
    const file = baseOf(f.location.path);
    const ecosystem = f.dependency.ecosystem as "npm" | "PyPI";
    const eco = ecosystem === "npm" ? npmEco(p, file) : pypiEco(p, file);
    const r = verdict(p, eco, graphFor(p, ecosystem, file), f.dependency.name, f.dependency.version);
    if (r.status === "unreachable") {
      const lower = SEVERITY_ORDER[Math.min(SEVERITY_ORDER.indexOf(f.severity) + 1, SEVERITY_ORDER.length - 1)]!;
      if (lower !== f.severity) {
        r.originalSeverity = f.severity;
        f.message += ` Likely unreachable: ${r.reason} Shown as ${lower} instead of ${f.severity}; still upgrade or remove it.`;
        f.severity = lower;
      } else {
        f.message += ` Likely unreachable: ${r.reason}`;
      }
    }
    f.reachability = r;
  }
}
