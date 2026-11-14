/**
 * The MCP tools: scan, explain, check_package. Only Finding data (minus code snippets) is returned:
 * tool results go to whatever model the client uses. See docs/specs/mcp-server.md.
 */
import { lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { SEVERITY_ORDER, sortFindings, type EngineName, type Finding } from "../core/finding.js";
import { isIgnored, loadIgnorePatterns } from "../core/ignore.js";
import { assessRefs, type PkgriskOptions } from "../engines/pkgrisk/index.js";
import { normalizePypi, type Ecosystem, type PkgRef } from "../engines/pkgrisk/manifests.js";
import { isValidName } from "../engines/pkgrisk/registry.js";
import { changedFiles, isBinary } from "../hook/git.js";
import { ALL_ENGINES, scan, type ScanOptions, type ScanResult } from "../scan.js";
import { ToolError, type Tool } from "./protocol.js";

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;
/** Bigger files are skipped in changed/paths scans: generated or minified, slow for Opengrep. */
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const CODE_ENGINES: EngineName[] = ["opengrep", "gitleaks"];
const DEP_ENGINES: EngineName[] = ["osv-scanner", "pkgrisk"];
const MANIFEST =
  /^(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|requirements[^/]*\.txt|pyproject\.toml|Pipfile(\.lock)?|poetry\.lock|uv\.lock|setup\.py|setup\.cfg)$/;

export interface ToolDeps {
  /** Replaces the real scanner (tests). */
  scan?: (target: string, opts: ScanOptions) => Promise<ScanResult>;
  /** Passed to pkgrisk by check_package (tests inject fetch / disable the cache). */
  pkgrisk?: PkgriskOptions;
}

// ---------- argument helpers ----------

function optString(args: Record<string, unknown>, key: string): string | undefined {
  const v = args[key];
  if (v === undefined) return undefined;
  if (typeof v !== "string" || v.length === 0) throw new ToolError(`\`${key}\` must be a non-empty string`);
  return v;
}

function optStrings(args: Record<string, unknown>, key: string): string[] | undefined {
  const v = args[key];
  if (v === undefined) return undefined;
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string" || x.length === 0)) {
    throw new ToolError(`\`${key}\` must be an array of non-empty strings`);
  }
  return v as string[];
}

function optBool(args: Record<string, unknown>, key: string): boolean | undefined {
  const v = args[key];
  if (v === undefined) return undefined;
  if (typeof v !== "boolean") throw new ToolError(`\`${key}\` must be true or false`);
  return v;
}

// ---------- output shaping (no snippets ever) ----------

function where(f: Finding): string {
  const { path, startLine, endLine } = f.location;
  return endLine && endLine !== startLine ? `${path}:${startLine}-${endLine}` : `${path}:${startLine}`;
}

/** One line's worth of a finding for the scan list. */
export function brief(f: Finding): Record<string, unknown> {
  return {
    id: f.id,
    severity: f.severity,
    ...(f.confidence ? { confidence: f.confidence } : {}),
    category: f.category,
    rule: f.ruleId,
    title: f.title,
    location: where(f),
    ...(f.dependency ? { package: `${f.dependency.name}@${f.dependency.version} (${f.dependency.ecosystem})` } : {}),
    ...(f.reachability ? { reachability: f.reachability.status } : {}),
  };
}

const cweLink = (cwe: string) => {
  const n = /^CWE-(\d+)/.exec(cwe)?.[1];
  return n ? `https://cwe.mitre.org/data/definitions/${n}.html` : undefined;
};

/** Everything about one finding, minus source code. */
export function detail(f: Finding): Record<string, unknown> {
  const { snippet: _, ...location } = f.location;
  return {
    id: f.id,
    severity: f.severity,
    ...(f.confidence ? { confidence: f.confidence } : {}),
    category: f.category,
    engine: f.engine,
    rule: f.ruleId,
    title: f.title,
    message: f.message,
    location,
    cwe: f.cwe.map((c) => ({ id: c, ...(cweLink(c) ? { url: cweLink(c) } : {}) })),
    owasp: f.owasp,
    ...(f.dependency ? { dependency: f.dependency } : {}),
    ...(f.reachability ? { reachability: f.reachability } : {}),
    ...(f.dataflow?.length ? { dataflow: f.dataflow.map(({ path, line }) => ({ path, line })) } : {}),
  };
}

function totals(findings: Finding[]): Record<string, number> {
  const t: Record<string, number> = {};
  for (const s of SEVERITY_ORDER) {
    const n = findings.filter((f) => f.severity === s).length;
    if (n) t[s] = n;
  }
  return t;
}

// ---------- paths ----------

/** Resolve a user-given path and refuse anything outside the server root (symlinks included). */
async function inside(root: string, p: string): Promise<string> {
  const abs = isAbsolute(p) ? p : resolve(root, p);
  let real: string;
  try {
    real = await realpath(abs);
  } catch {
    throw new ToolError(`no such file: ${p}`);
  }
  if (real !== root && !real.startsWith(root + sep)) throw new ToolError(`${p} is outside the project root ${root}`);
  return relative(root, real).split(sep).join("/");
}

/** Copy the given root-relative files into dest. Returns which were copied and which were skipped. */
async function copyFiles(root: string, dest: string, files: string[], ignores: string[]) {
  const copied: string[] = [];
  const skipped: string[] = [];
  for (const rel of files) {
    if (isIgnored(rel, ignores)) continue;
    const src = join(root, rel);
    const st = await lstat(src).catch(() => undefined);
    if (!st?.isFile()) continue; // deleted, directory, symlink, socket...
    if (st.size > MAX_FILE_BYTES) {
      skipped.push(`${rel} (over 2 MB)`);
      continue;
    }
    const buf = await readFile(src);
    if (isBinary(buf)) continue;
    const out = resolve(dest, rel);
    if (!out.startsWith(dest + sep)) continue;
    await mkdir(dirname(out), { recursive: true });
    await writeFile(out, buf);
    copied.push(rel);
  }
  return { copied, skipped };
}

// ---------- tools ----------

export function createTools(rootArg: string, deps: ToolDeps = {}): Tool[] {
  const runScan = deps.scan ?? scan;
  let rootPromise: Promise<string> | undefined;
  const getRoot = () => (rootPromise ??= realpath(resolve(rootArg)));
  /** Findings from the latest scan, for `explain`. */
  let last = new Map<string, Finding>();

  const scanTool: Tool = {
    name: "scan",
    title: "Vigil security scan",
    description:
      "Scan the project for security problems: vulnerable code patterns (injection, XSS, SSRF, unsafe deserialization, ...), " +
      "hardcoded secrets, and risky or vulnerable npm/PyPI dependencies. By default only files changed since the last commit " +
      "(plus untracked files) are scanned — call it after editing code. Use scope \"all\" for the whole project, or `paths` for " +
      "specific files. Returns a short list sorted by severity; call `explain` with a finding's id for details and how to fix it.",
    inputSchema: {
      type: "object",
      properties: {
        scope: {
          type: "string",
          enum: ["changed", "all"],
          description: "\"changed\" (default): files changed vs HEAD plus untracked files. \"all\": the whole project (slower).",
        },
        paths: {
          type: "array",
          items: { type: "string" },
          description: "Scan only these files (relative to the project root). Overrides scope.",
        },
        engines: {
          type: "array",
          items: { type: "string", enum: ALL_ENGINES },
          description: "Subset of engines to run. Default: all.",
        },
        offline: { type: "boolean", description: "Skip npm/PyPI registry lookups. Default false." },
        limit: { type: "integer", minimum: 1, maximum: MAX_LIMIT, description: `Max findings returned (default ${DEFAULT_LIMIT}).` },
      },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
    handler: async (args) => {
      const root = await getRoot();
      const scope = optString(args, "scope") ?? "changed";
      if (scope !== "changed" && scope !== "all") throw new ToolError('`scope` must be "changed" or "all"');
      const paths = optStrings(args, "paths");
      const engineArg = optStrings(args, "engines");
      for (const e of engineArg ?? []) {
        if (!ALL_ENGINES.includes(e as EngineName)) throw new ToolError(`unknown engine "${e}" (have: ${ALL_ENGINES.join(", ")})`);
      }
      const engines = (engineArg as EngineName[] | undefined) ?? ALL_ENGINES;
      const offline = optBool(args, "offline") ?? false;
      const limitArg = args.limit;
      if (limitArg !== undefined && (typeof limitArg !== "number" || !Number.isInteger(limitArg) || limitArg < 1)) {
        throw new ToolError("`limit` must be a positive integer");
      }
      const limit = Math.min((limitArg as number | undefined) ?? DEFAULT_LIMIT, MAX_LIMIT);

      let result: ScanResult;
      let files: string[] | undefined;
      const notes: string[] = [];
      const mode = paths ? "paths" : scope;

      if (mode === "all") {
        result = await runScan(root, { engines, offline });
      } else {
        let selected: string[];
        if (paths) selected = await Promise.all(paths.map((p) => inside(root, p)));
        else {
          try {
            selected = await changedFiles(root);
          } catch {
            throw new ToolError(`${root} is not a git repository, so there are no "changed" files. Use scope "all" or pass \`paths\`.`);
          }
        }
        const ignores = await loadIgnorePatterns(root);
        const codeEngines = engines.filter((e) => CODE_ENGINES.includes(e));
        const depEngines = engines.filter((e) => DEP_ENGINES.includes(e));
        const depsChanged = selected.some((f) => MANIFEST.test(basename(f)));
        const parts: ScanResult[] = [];

        const tmp = await mkdtemp(join(tmpdir(), "vigil-mcp-")); // mode 0700
        try {
          const dest = await realpath(tmp);
          const { copied, skipped } = await copyFiles(root, dest, selected, ignores);
          files = copied;
          if (skipped.length) notes.push(`skipped: ${skipped.join(", ")}`);
          if (copied.length && codeEngines.length) {
            const r = await runScan(dest, { engines: codeEngines, reachability: false, ignoreFile: join(root, ".vigilignore") });
            const fix = (s: string) => s.split(dest).join(root);
            parts.push({ ...r, warnings: r.warnings.map(fix), engines: r.engines.map((e) => (e.error ? { ...e, error: fix(e.error) } : e)) });
          }
        } finally {
          await rm(tmp, { recursive: true, force: true });
        }
        if (depsChanged && depEngines.length) {
          parts.push(await runScan(root, { engines: depEngines, offline }));
          notes.push("a dependency manifest changed, so dependencies were checked for the whole project");
        }
        if (!parts.length) {
          last = new Map();
          return {
            root,
            scope: mode,
            files,
            totals: {},
            shown: 0,
            findings: [],
            hint: mode === "changed" ? 'No changed files to scan. Use scope "all" to scan the whole project.' : "Nothing to scan in those paths.",
          };
        }
        result = {
          root,
          findings: sortFindings(parts.flatMap((p) => p.findings)),
          ignores: parts[0]!.ignores,
          warnings: parts.flatMap((p) => p.warnings),
          engines: parts.flatMap((p) => p.engines),
        };
      }

      last = new Map(result.findings.map((f) => [f.id, f]));
      const shown = result.findings.slice(0, limit);
      const failed = result.engines.filter((e) => !e.ok).map((e) => `${e.engine}: ${e.error ?? "failed"}`);
      return {
        root,
        scope: mode,
        ...(files ? { files } : {}),
        totals: totals(result.findings),
        shown: shown.length,
        findings: shown.map(brief),
        ...(result.ignores.length ? { vigilignore: result.ignores } : {}),
        ...(failed.length ? { engine_errors: failed } : {}),
        ...(result.warnings.length || notes.length ? { warnings: [...notes, ...result.warnings] } : {}),
        ...(result.findings.length > shown.length
          ? { hint: `${result.findings.length - shown.length} more not shown. Raise \`limit\`, or narrow with \`paths\`.` }
          : {}),
      };
    },
  };

  const explainTool: Tool = {
    name: "explain",
    title: "Explain a Vigil finding",
    description:
      "Full detail for one finding from the latest `scan`: what is wrong, why it matters and how to fix it, CWE/OWASP " +
      "references, the source-to-sink path for injection findings, reachability evidence and fixed versions for vulnerable dependencies.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string", description: "A finding id from the latest scan." } },
      required: ["id"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
    handler: async (args) => {
      const id = optString(args, "id");
      if (!id) throw new ToolError("`id` is required");
      const f = last.get(id);
      if (!f) throw new ToolError(`no finding with id ${id} in the latest scan. Run \`scan\` again first.`);
      return detail(f);
    },
  };

  const checkPackageTool: Tool = {
    name: "check_package",
    title: "Check a package before installing it",
    description:
      "Call this BEFORE adding or installing any npm or PyPI dependency. Checks that the package exists (AI assistants often " +
      "invent package names, and attackers register them), that it is not a typosquat of a popular package, and that the " +
      "package or version is not brand-new. verdict: \"block\" = do not install; \"caution\" = verify the publisher first; " +
      "\"ok\" = no red flags found; \"unverified\" = the registry could not be reached.",
    inputSchema: {
      type: "object",
      properties: {
        ecosystem: { type: "string", enum: ["npm", "PyPI"] },
        name: { type: "string", description: "Package name exactly as you would install it." },
        version: { type: "string", description: "Exact version you plan to install (optional)." },
      },
      required: ["ecosystem", "name"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
    handler: async (args) => {
      const eco = optString(args, "ecosystem");
      const ecosystem: Ecosystem | undefined = eco === "npm" ? "npm" : eco?.toLowerCase() === "pypi" ? "PyPI" : undefined;
      if (!ecosystem) throw new ToolError('`ecosystem` must be "npm" or "PyPI"');
      const raw = optString(args, "name");
      if (!raw) throw new ToolError("`name` is required");
      const name = ecosystem === "PyPI" ? normalizePypi(raw.trim()) : raw.trim();
      if (!isValidName(ecosystem, name)) throw new ToolError(`"${raw}" is not a valid ${ecosystem} package name`);
      const version = optString(args, "version")?.trim();

      const ref: PkgRef = { ecosystem, name, ...(version ? { version } : {}), direct: true, file: "(check_package)", line: 1 };
      const out = await assessRefs([ref], [], deps.pkgrisk ?? {});
      const rules = new Set(out.findings.map((f) => f.ruleId));
      const unreachable = out.warnings.some((w) => w.includes("registry unreachable"));
      const verdict =
        rules.has("pkg-nonexistent") || rules.has("pkg-typosquat")
          ? "block"
          : out.findings.length
            ? "caution"
            : unreachable
              ? "unverified"
              : "ok";
      return {
        package: `${name}${version ? `@${version}` : ""}`,
        ecosystem,
        verdict,
        findings: sortFindings(out.findings).map((f) => ({ rule: f.ruleId, severity: f.severity, title: f.title, message: f.message })),
        notes: [
          ...out.warnings.map((w) => w.replace(/^pkgrisk: /, "")),
          "Install scripts are not checked here (that needs a lockfile); `scan` covers them after install.",
        ],
      };
    },
  };

  return [scanTool, explainTool, checkPackageTool];
}

export const INSTRUCTIONS =
  "Vigil is a local security scanner. Call `check_package` before adding any npm or PyPI dependency. " +
  "Call `scan` after you change code (it checks changed files by default), then `explain` for details on a finding. " +
  "Source code stays on this machine; only finding metadata is returned.";

