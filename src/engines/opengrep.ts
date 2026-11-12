import { fileURLToPath } from "node:url";
import {
  collapseOverlaps,
  fingerprint,
  normalizeCode,
  redactStringLiterals,
  type DataflowStep,
  type Finding,
  type Severity,
} from "../core/finding.js";
import { toRelative } from "./paths.js";
import { run } from "./run.js";
import type { EngineOutput } from "./types.js";

export const RULES_DIR = fileURLToPath(new URL("../../rules", import.meta.url));

interface OgPos {
  line: number;
  col: number;
}
interface OgLoc {
  path: string;
  start: OgPos;
  end: OgPos;
}
type OgCliLoc = ["CliLoc", [OgLoc, string]];

interface OgResult {
  check_id: string;
  path: string;
  start: OgPos;
  end: OgPos;
  extra: {
    message: string;
    severity: string;
    lines?: string;
    metadata?: Record<string, unknown>;
    dataflow_trace?: {
      taint_source?: OgCliLoc;
      intermediate_vars?: { location: OgLoc; content: string }[];
      taint_sink?: OgCliLoc;
    };
  };
}

export interface OgError {
  type?: string | unknown[];
  level?: string;
  message?: string;
  path?: string;
}

export interface OgOutput {
  results: OgResult[];
  errors: OgError[];
}

/** Rules for hardcoded credentials: their matched code contains the secret itself. */
const CREDENTIAL_CWES = new Set(["CWE-798", "CWE-259", "CWE-321", "CWE-547"]);

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function mapSeverity(engineSeverity: string, metadata: Record<string, unknown>): Severity {
  const override = metadata["severity"];
  if (typeof override === "string" && SEVERITIES.includes(override as Severity)) return override as Severity;
  if (engineSeverity === "ERROR") return "high";
  if (engineSeverity === "WARNING") return "medium";
  return "low";
}

function asList(v: unknown): string[] {
  if (Array.isArray(v)) return v.map(String);
  return typeof v === "string" ? [v] : [];
}

/** "CWE-78: Improper Neutralization..." → "CWE-78" */
function cweIds(v: unknown): string[] {
  return asList(v).map((s) => s.match(/CWE-\d+/)?.[0] ?? s);
}

function confidence(v: unknown): Finding["confidence"] {
  const s = String(v ?? "").toLowerCase();
  return s === "high" || s === "medium" || s === "low" ? s : undefined;
}

/** Opengrep prefixes rule ids with the config directory path; our ids contain no dots. */
export function ruleIdOf(checkId: string): string {
  return checkId.split(".").pop() ?? checkId;
}

function dataflow(root: string, r: OgResult, clean: (s: string) => string): DataflowStep[] | undefined {
  const t = r.extra.dataflow_trace;
  if (!t) return undefined;
  const steps: DataflowStep[] = [];
  const push = (loc: OgLoc, snippet: string) =>
    steps.push({ path: toRelative(root, loc.path), line: loc.start.line, snippet: clean(snippet) });
  if (t.taint_source?.[0] === "CliLoc") push(...t.taint_source[1]);
  for (const v of t.intermediate_vars ?? []) push(v.location, v.content);
  if (t.taint_sink?.[0] === "CliLoc") push(...t.taint_sink[1]);
  return steps.length ? steps : undefined;
}

export function normalizeOpengrep(root: string, out: OgOutput): Finding[] {
  const occurrences = new Map<string, number>();
  // A taint rule reports one result per source reaching the same sink; keep one per range.
  const ranges = new Set<string>();
  const results = out.results.filter((r) => {
    const key = [r.check_id, r.path, r.start.line, r.start.col, r.end.line, r.end.col].join("\u0000");
    return ranges.has(key) ? false : (ranges.add(key), true);
  });
  return results.map((r) => {
    const meta = r.extra.metadata ?? {};
    const ruleId = ruleIdOf(r.check_id);
    const path = toRelative(root, r.path);
    const cwe = cweIds(meta["cwe"]);
    // Never let a hardcoded secret reach the Finding: redact literals in every
    // excerpt, and fingerprint the redacted code so the hash is not an oracle.
    const clean = cwe.some((c) => CREDENTIAL_CWES.has(c)) ? redactStringLiterals : (s: string) => s;
    const lines = r.extra.lines === undefined ? undefined : clean(r.extra.lines);
    const code = normalizeCode(lines ?? "");
    const key = `${ruleId}|${path}|${code}`;
    const n = occurrences.get(key) ?? 0;
    occurrences.set(key, n + 1);
    return {
      id: fingerprint("opengrep", ruleId, path, code, String(n)),
      category: "code",
      engine: "opengrep",
      ruleId,
      title: typeof meta["title"] === "string" ? meta["title"] : ruleId,
      message: r.extra.message.trim(),
      severity: mapSeverity(r.extra.severity, meta),
      confidence: confidence(meta["confidence"]),
      location: {
        path,
        startLine: r.start.line,
        endLine: r.end.line,
        startColumn: r.start.col,
        snippet: lines?.trim(),
      },
      cwe,
      owasp: asList(meta["owasp"]),
      dataflow: dataflow(root, r, clean),
    } satisfies Finding;
  });
}

/**
 * Engine errors about a target file can quote its source, so for those keep only
 * the error type and path. Errors without a path concern our own rules.
 */
export function describeError(root: string, e: OgError): string {
  const type = Array.isArray(e.type) ? String(e.type[0]) : (e.type ?? "error");
  if (e.path) return `opengrep: ${type} in ${toRelative(root, e.path)}`;
  return `opengrep: ${e.message ?? type}`.slice(0, 300);
}

export async function runOpengrep(bin: string, root: string, ignores: string[]): Promise<EngineOutput> {
  // `--exclude=<p>` (not two argv items) so a pattern can never be read as a flag.
  const excludes = ignores.map((p) => `--exclude=${p.replace(/\/$/, "")}`);
  const args = [
    "scan",
    `--config=${RULES_DIR}`,
    "--json",
    "--quiet",
    // The scanned repo is untrusted: it must not be able to silence findings with
    // inline `nosemgrep` comments or its own .semgrepignore. Suppression goes
    // through .vigilignore only, which every report lists.
    "--disable-nosem",
    "--x-ignore-semgrepignore-files",
    ...excludes,
    "--",
    ".",
  ];
  const res = await run(bin, args, { cwd: root });
  if (res.code !== 0 && !res.stdout.trim().startsWith("{")) {
    throw new Error(`opengrep exited ${res.code}: ${res.stderr.trim().slice(0, 500)}`);
  }
  const out = JSON.parse(res.stdout) as OgOutput;
  const warnings = out.errors.map((e) => describeError(root, e));
  return { findings: collapseOverlaps(normalizeOpengrep(root, out)), warnings };
}
