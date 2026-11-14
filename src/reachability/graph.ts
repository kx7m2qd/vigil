/**
 * Dependency graphs from lockfiles: which installed package pulls in which. Reachability needs this
 * to tell "nothing uses X" from "nothing *imports* X, but a package you do use depends on it".
 *
 * Supported: package-lock.json (v1-v3), yarn.lock (classic and berry), bun.lock, pip-compile / uv pip compile
 * requirements (`# via` comments), poetry.lock, uv.lock. Anything else → no graph → no
 * "unreachable" verdicts. Every parser is lenient: an edge it can't resolve is dropped, which can
 * only leave a package orphaned (→ "unknown"), never wrongly connected.
 */
import { normalizePypi } from "../engines/pkgrisk/manifests.js";

export interface DepNode {
  name: string;
  version?: string;
}

export interface DepGraph {
  nodes: Map<string, DepNode>;
  /** child key → keys of the packages that depend on it. */
  parents: Map<string, Set<string>>;
  /** Keys of the project's own production dependencies. */
  roots: Set<string>;
  /** Keys of the project's own dev/test dependencies. */
  devRoots: Set<string>;
}

export interface DeclaredDeps {
  prod: Map<string, string>;
  dev: Map<string, string>;
}

const newGraph = (): DepGraph => ({ nodes: new Map(), parents: new Map(), roots: new Set(), devRoots: new Set() });

function edge(g: DepGraph, parent: string, child: string): void {
  if (parent === child) return;
  let s = g.parents.get(child);
  if (!s) g.parents.set(child, (s = new Set()));
  s.add(parent);
}

/** Every node for this package; only the ones at `version` when any match it. */
export function keysFor(g: DepGraph, name: string, version?: string): string[] {
  const all = [...g.nodes.entries()].filter(([, n]) => n.name === name).map(([k]) => k);
  const exact = version ? all.filter((k) => g.nodes.get(k)?.version === version) : [];
  return exact.length ? exact : all;
}

// ---- npm: package-lock.json ------------------------------------------------

type LockEntry = {
  name?: string;
  version?: string;
  link?: boolean;
  resolved?: string;
  dependencies?: Record<string, unknown>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  requires?: Record<string, string>;
};

const lastName = (key: string): string => key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);

/** "node_modules/a/node_modules/b" → "node_modules/a"; "node_modules/a" or "packages/web" → "". */
function parentDir(key: string): string {
  const i = key.lastIndexOf("node_modules/");
  return i <= 0 ? "" : key.slice(0, i).replace(/\/$/, "");
}

export function npmLockGraph(text: string, declared?: DeclaredDeps): DepGraph | undefined {
  let lock: { packages?: Record<string, LockEntry>; dependencies?: Record<string, LockEntry> };
  try {
    lock = JSON.parse(text) as typeof lock;
  } catch {
    return undefined;
  }
  const packages: Record<string, LockEntry> = {};
  if (lock.packages) Object.assign(packages, lock.packages);
  else if (lock.dependencies) {
    // v1: nested `dependencies`, edges in `requires`.
    const flatten = (deps: Record<string, LockEntry>, base: string) => {
      for (const [name, e] of Object.entries(deps)) {
        const key = `${base ? `${base}/` : ""}node_modules/${name}`;
        packages[key] = { ...e, dependencies: e.requires };
        if (e.dependencies) flatten(e.dependencies as Record<string, LockEntry>, key);
      }
    };
    flatten(lock.dependencies, "");
  } else return undefined;

  const g = newGraph();
  for (const [key, e] of Object.entries(packages)) {
    if (key === "" || e.link) continue;
    const name = key.includes("node_modules/") ? lastName(key) : (e.name ?? key);
    g.nodes.set(key, { name, version: e.version });
    // Aliases (`"x": "npm:real@1"`): advisories name the real package.
    if (e.name && e.name !== name && key.includes("node_modules/")) g.nodes.set(`${key}#alias`, { name: e.name, version: e.version });
  }

  const resolve = (from: string, name: string): string | undefined => {
    for (let base = from; ; base = parentDir(base)) {
      const cand = `${base ? `${base}/` : ""}node_modules/${name}`;
      const e = packages[cand];
      if (e) return e.link && e.resolved !== undefined ? e.resolved : cand;
      if (!base) return undefined;
    }
  };
  const link = (from: string, child: string) => {
    edge(g, from, child);
    if (g.nodes.has(`${child}#alias`)) edge(g, from, `${child}#alias`);
  };

  for (const [key, e] of Object.entries(packages)) {
    if (e.link) continue;
    const isProject = key === "" || !key.includes("node_modules/");
    const prodNames = Object.keys({ ...(e.dependencies ?? {}), ...(e.optionalDependencies ?? {}), ...(e.peerDependencies ?? {}) });
    for (const name of prodNames) {
      const child = resolve(key, name);
      if (!child) continue;
      if (isProject) {
        g.roots.add(child);
        if (g.nodes.has(`${child}#alias`)) g.roots.add(`${child}#alias`);
      } else link(key, child);
    }
    if (isProject) {
      for (const name of Object.keys(e.devDependencies ?? {})) {
        const child = resolve(key, name);
        if (child) g.devRoots.add(child);
      }
    }
  }
  // v1 locks (and v2 locks without a root entry) don't list the project's own dependencies.
  if (!packages[""] && declared) {
    for (const name of declared.prod.keys()) {
      const k = resolve("", name);
      if (k) g.roots.add(k);
    }
    for (const name of declared.dev.keys()) {
      const k = resolve("", name);
      if (k) g.devRoots.add(k);
    }
  }
  // Bundled packages are physically nested under their parent without being listed as its deps.
  for (const key of g.nodes.keys()) {
    const base = key.replace(/#alias$/, "");
    if (!g.parents.has(key) && !g.roots.has(key) && !g.devRoots.has(key)) {
      const p = parentDir(base);
      if (p && g.nodes.has(p)) edge(g, p, key);
    }
  }
  return g;
}

// ---- npm: yarn.lock (classic v1 and berry) ---------------------------------

/** `"@a/b@^1", @a/b@npm:~1.2` → [["@a/b", "^1"], ["@a/b", "npm:~1.2"]] */
function descriptors(header: string): [string, string][] {
  return header
    .split(/,\s*/)
    .map((d) => d.trim().replace(/^"|"$/g, ""))
    .map((d): [string, string] => {
      const at = d.indexOf("@", 1);
      return at === -1 ? [d, ""] : [d.slice(0, at), d.slice(at + 1)];
    });
}

export function yarnLockGraph(text: string, declared: DeclaredDeps | undefined): DepGraph | undefined {
  const g = newGraph();
  const byDescriptor = new Map<string, string>();
  const pending: { from: string; name: string; range: string }[] = [];
  const workspaces: string[] = [];
  let current: string | undefined;
  let inDeps = false;
  let pendingDescs: [string, string][] = [];

  const norm = (range: string) => range.replace(/^npm:/, "");
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    if (!line.startsWith(" ")) {
      if (!line.endsWith(":")) continue;
      pendingDescs = descriptors(line.slice(0, -1));
      current = undefined;
      inDeps = false;
      continue;
    }
    const indent = line.length - line.trimStart().length;
    const t = line.trim();
    if (indent === 2) {
      inDeps = /^(?:dependencies|optionalDependencies|peerDependencies):$/.test(t);
      const v = /^version:?\s+"?([^"\s]+)"?$/.exec(t);
      if (v && pendingDescs.length) {
        const name = (pendingDescs[0] as [string, string])[0];
        current = `${name}@${v[1]}`;
        if (!g.nodes.has(current)) g.nodes.set(current, { name, version: v[1] });
        for (const [n, r] of pendingDescs) byDescriptor.set(`${n}@${norm(r)}`, current);
        if (pendingDescs.some(([, r]) => r.startsWith("workspace:"))) workspaces.push(current);
      }
      continue;
    }
    if (indent >= 4 && inDeps && current) {
      const m = /^"?((?:@[^@"\s/]+\/)?[^@"\s:]+)"?:?\s+"?([^"]*)"?$/.exec(t);
      if (m) pending.push({ from: current, name: m[1] as string, range: norm(m[2] as string) });
    }
  }
  if (!g.nodes.size) return undefined;

  const byName = (name: string) => [...g.nodes.entries()].filter(([, n]) => n.name === name).map(([k]) => k);
  const find = (name: string, range: string): string[] => {
    const k = byDescriptor.get(`${name}@${range}`);
    if (k) return [k];
    const all = byName(name);
    return all.length === 1 ? all : all; // ambiguous: link to every version (over-connecting is the safe side)
  };
  const ws = new Set(workspaces);
  for (const p of pending) {
    for (const child of find(p.name, p.range)) {
      if (ws.has(p.from)) {
        // Berry workspace entries merge dev and prod deps; package.json says which is which.
        if (declared?.dev.has(p.name) && !declared.prod.has(p.name)) g.devRoots.add(child);
        else g.roots.add(child);
      } else edge(g, p.from, child);
    }
  }
  for (const w of ws) g.nodes.delete(w);
  if (!ws.size && declared) {
    for (const [name, range] of declared.prod) for (const k of find(name, range)) g.roots.add(k);
    for (const [name, range] of declared.dev) for (const k of find(name, range)) g.devRoots.add(k);
  }
  return g;
}

// ---- npm: bun.lock (text format, lockfileVersion 0/1) ----------------------

/** JSONC → JSON: drops `//` and block comments and trailing commas, leaving strings alone. */
export function stripJsonc(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j;
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end === -1 ? text.length : end + 1;
    } else if (c === ",") {
      let j = i + 1;
      while (/\s/.test(text[j] ?? "")) j++;
      if (text[j] !== "}" && text[j] !== "]") out += c;
    } else out += c;
  }
  return out;
}

type BunDeps = { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string> };

/** `"@a/b/c/@d/e"` → `["@a/b", "c", "@d/e"]`: an install path is a chain of package names. */
function bunPath(key: string): string[] {
  const parts = key.split("/");
  const out: string[] = [];
  for (let i = 0; i < parts.length; i++) out.push((parts[i] as string).startsWith("@") ? `${parts[i]}/${parts[++i] ?? ""}` : (parts[i] as string));
  return out;
}

/**
 * bun.lock: `workspaces` holds each workspace's declared deps, `packages` maps an install path
 * (`"debug"`, or `"express/debug"` for a copy nested under express) to `["name@version", registry,
 * { dependencies, ... }, integrity]`. A dependency resolves like node_modules: nearest enclosing path.
 */
export function bunLockGraph(text: string): DepGraph | undefined {
  let lock: { workspaces?: Record<string, BunDeps & { name?: string; devDependencies?: Record<string, string> }>; packages?: Record<string, unknown[]> };
  try {
    lock = JSON.parse(stripJsonc(text)) as typeof lock;
  } catch {
    return undefined;
  }
  if (!lock.packages || typeof lock.packages !== "object") return undefined;
  const g = newGraph();
  const info = new Map<string, BunDeps>();
  for (const [key, entry] of Object.entries(lock.packages)) {
    if (!Array.isArray(entry) || typeof entry[0] !== "string") continue;
    const spec = entry[0];
    const at = spec.indexOf("@", 1);
    const name = at === -1 ? spec : spec.slice(0, at);
    const version = at === -1 ? undefined : spec.slice(at + 1);
    if (version?.startsWith("workspace:")) continue; // the project's own packages
    g.nodes.set(key, { name, version });
    // Registry entries have the info object third; git/tarball entries have it second.
    const obj = entry.find((e, i) => i > 0 && e && typeof e === "object" && !Array.isArray(e)) as BunDeps | undefined;
    if (obj) info.set(key, obj);
  }
  if (!g.nodes.size) return undefined;

  const resolve = (fromPath: string[], name: string): string | undefined => {
    for (let n = fromPath.length; n >= 0; n--) {
      const cand = [...fromPath.slice(0, n), name].join("/");
      if (g.nodes.has(cand)) return cand;
    }
    return undefined;
  };
  const depNames = (d: BunDeps) => Object.keys({ ...(d.dependencies ?? {}), ...(d.optionalDependencies ?? {}), ...(d.peerDependencies ?? {}) });

  for (const [key, d] of info) {
    const path = bunPath(key);
    for (const dep of depNames(d)) {
      const child = resolve(path, dep);
      if (child) edge(g, key, child);
    }
  }
  // Workspace deps are the roots. A version specific to one workspace is nested under its name.
  for (const ws of Object.values(lock.workspaces ?? {})) {
    const base = ws.name ? [ws.name] : [];
    for (const dep of depNames(ws)) {
      const k = resolve(base, dep);
      if (k) g.roots.add(k);
    }
    for (const dep of Object.keys(ws.devDependencies ?? {})) {
      const k = resolve(base, dep);
      if (k) g.devRoots.add(k);
    }
  }
  return g;
}

// ---- PyPI ------------------------------------------------------------------

/** pip-compile / `uv pip compile` output: each pin is followed by `# via <parents>` comments. */
export function pipCompileGraph(files: { text: string; dev: boolean }[]): DepGraph | undefined {
  const compiled = files.filter((f) => /^\s+#\s+via\b/m.test(f.text));
  if (!compiled.length) return undefined;
  const g = newGraph();
  const via = new Map<string, Set<string>>();
  const rootOf = new Map<string, boolean>(); // name → dev?
  for (const f of compiled) {
    let current: string | undefined;
    let sawVia = false;
    const close = () => {
      if (current && !sawVia) rootOf.set(current, f.dev); // no annotation: treat as declared
    };
    for (const raw of f.text.split("\n")) {
      const line = raw.replace(/\r$/, "");
      const req = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;\\#]+)/.exec(line);
      if (req) {
        close();
        current = normalizePypi(req[1] as string);
        sawVia = false;
        g.nodes.set(current, { name: current, version: req[2] });
        continue;
      }
      if (!current) continue;
      const c = /^\s*#\s*(?:via\s+)?(.*)$/.exec(line);
      if (!c || !line.trim().startsWith("#")) continue;
      if (/^\s*#\s*via\b/.test(line)) sawVia = true;
      else if (!sawVia) continue;
      const who = (c[1] ?? "").trim();
      if (!who || who === "via") continue;
      if (/^-[rc]\b/.test(who) || /^(?:-e|file:|\.)/.test(who)) {
        rootOf.set(current, f.dev && rootOf.get(current) !== false);
        continue;
      }
      const parent = /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(who)?.[1];
      if (parent) {
        let s = via.get(current);
        if (!s) via.set(current, (s = new Set()));
        s.add(normalizePypi(parent));
      }
    }
    close();
  }
  for (const [child, ps] of via) for (const p of ps) if (g.nodes.has(p)) edge(g, p, child);
  for (const [name, dev] of rootOf) (dev ? g.devRoots : g.roots).add(name);
  return g;
}

/** Splits a TOML lockfile into `[[package]]` blocks, each with its sub-tables. Line-based on purpose. */
function tomlPackages(text: string): { fields: Map<string, string>; tables: Map<string, string[]> }[] {
  const out: { fields: Map<string, string>; tables: Map<string, string[]> }[] = [];
  let cur: (typeof out)[number] | undefined;
  let table = "";
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (/^\[\[package\]\]\s*$/.test(line)) {
      cur = { fields: new Map(), tables: new Map() };
      out.push(cur);
      table = "";
      continue;
    }
    const h = /^\[([^\]]+)\]\s*$/.exec(line);
    if (h) {
      table = h[1]!.startsWith("package.") ? h[1]!.slice("package.".length) : "\0other";
      if (table === "\0other") cur = undefined;
      continue;
    }
    if (!cur) continue;
    if (!table) {
      const f = /^([\w-]+)\s*=\s*(.*)$/.exec(line);
      if (f) cur.fields.set(f[1] as string, f[2] as string);
      // multi-line arrays at package level (uv: dependencies = [ ... ])
      if (f || /^\s/.test(line) || line.startsWith("]")) {
        const key = f ? (f[1] as string) : [...cur.fields.keys()].pop();
        if (key) {
          const lines = cur.tables.get(`=${key}`) ?? [];
          lines.push(line);
          cur.tables.set(`=${key}`, lines);
        }
      }
      continue;
    }
    const lines = cur.tables.get(table) ?? [];
    lines.push(line);
    cur.tables.set(table, lines);
  }
  return out;
}

const tomlStr = (v: string | undefined) => /^"([^"]*)"/.exec(v ?? "")?.[1];
const namesIn = (lines: string[] | undefined) => [...(lines ?? []).join("\n").matchAll(/\bname\s*=\s*"([^"]+)"/g)].map((m) => normalizePypi(m[1] as string));

export function uvLockGraph(text: string): DepGraph | undefined {
  const pkgs = tomlPackages(text);
  if (!pkgs.length) return undefined;
  const g = newGraph();
  const projects = new Set<string>();
  for (const p of pkgs) {
    const name = tomlStr(p.fields.get("name"));
    if (!name) continue;
    const key = normalizePypi(name);
    if (/\b(?:virtual|editable)\s*=/.test(p.fields.get("source") ?? "")) projects.add(key);
    else g.nodes.set(key, { name: key, version: tomlStr(p.fields.get("version")) });
  }
  for (const p of pkgs) {
    const key = normalizePypi(tomlStr(p.fields.get("name")) ?? "");
    const isProject = projects.has(key);
    const prod = [...namesIn(p.tables.get("=dependencies")), ...namesIn(p.tables.get("optional-dependencies"))];
    const dev = namesIn(p.tables.get("dev-dependencies"));
    for (const child of prod) {
      if (projects.has(child)) continue;
      if (isProject) g.roots.add(child);
      else edge(g, key, child);
    }
    for (const child of dev) if (isProject && !projects.has(child)) g.devRoots.add(child);
  }
  return projects.size ? g : undefined;
}

/** poetry.lock has no root entry: the project's own dependencies come from pyproject.toml. */
export function poetryLockGraph(lock: string, pyproject: string | undefined): DepGraph | undefined {
  const pkgs = tomlPackages(lock);
  if (!pkgs.length || pyproject === undefined) return undefined;
  const g = newGraph();
  for (const p of pkgs) {
    const name = tomlStr(p.fields.get("name"));
    if (name) g.nodes.set(normalizePypi(name), { name: normalizePypi(name), version: tomlStr(p.fields.get("version")) });
  }
  for (const p of pkgs) {
    const key = normalizePypi(tomlStr(p.fields.get("name")) ?? "");
    for (const l of p.tables.get("dependencies") ?? []) {
      const m = /^"?([A-Za-z0-9][\w.-]*)"?\s*=/.exec(l);
      if (m && g.nodes.has(normalizePypi(m[1] as string))) edge(g, key, normalizePypi(m[1] as string));
    }
  }
  const declared = poetryDeclared(pyproject);
  for (const n of declared.prod) if (g.nodes.has(n)) g.roots.add(n);
  for (const n of declared.dev) if (g.nodes.has(n)) g.devRoots.add(n);
  return g.roots.size || g.devRoots.size ? g : undefined;
}

/** Direct dependencies from pyproject.toml: Poetry tables, PEP 621 `[project]`, and dependency groups. */
export function poetryDeclared(text: string): { prod: Set<string>; dev: Set<string> } {
  const prod = new Set<string>();
  const dev = new Set<string>();
  // table: Poetry-style `name = ...` lines; arrays: `key = [ "req", ... ]` where `keys` says which arrays count.
  let mode: { kind: "table" | "arrays"; into: Set<string>; keys?: string } | undefined;
  let inArray = false;
  for (const raw of text.split("\n")) {
    const line = raw.replace(/#.*$/, "").replace(/\r$/, "");
    const h = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (h) {
      const t = h[1]!.trim();
      mode =
        t === "tool.poetry.dependencies"
          ? { kind: "table", into: prod }
          : t === "tool.poetry.dev-dependencies" || /^tool\.poetry\.group\.[^.]+\.dependencies$/.test(t)
            ? { kind: "table", into: dev }
            : t === "project"
              ? { kind: "arrays", into: prod, keys: "dependencies" }
              : t === "project.optional-dependencies"
                ? { kind: "arrays", into: prod }
                : t === "dependency-groups"
                  ? { kind: "arrays", into: dev }
                  : undefined;
      inArray = false;
      continue;
    }
    if (!mode) continue;
    if (mode.kind === "table") {
      const m = /^\s*"?([A-Za-z0-9][\w.-]*)"?\s*=/.exec(line);
      if (m && m[1]!.toLowerCase() !== "python") mode.into.add(normalizePypi(m[1] as string));
      continue;
    }
    const start = /^\s*([\w-]+)\s*=\s*\[/.exec(line);
    if (start) inArray = mode.keys === undefined || start[1] === mode.keys;
    if (!inArray) continue;
    const body = start ? line.slice(line.indexOf("[") + 1) : line;
    for (const m of body.matchAll(/["']([A-Za-z0-9][\w.-]*)/g)) mode.into.add(normalizePypi(m[1] as string));
    if (body.replace(/"[^"]*"|'[^']*'/g, "").includes("]")) inArray = false; // `"uvicorn[standard]"` doesn't close it
  }
  return { prod, dev };
}
