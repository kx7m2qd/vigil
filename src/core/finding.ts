import { createHash, scryptSync } from "node:crypto";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Category = "code" | "dependency" | "secret";
export type EngineName = "opengrep" | "osv-scanner" | "gitleaks";

export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Location {
  /** Path relative to the scan root, always with forward slashes. */
  path: string;
  startLine: number;
  endLine?: number;
  startColumn?: number;
  /** Source excerpt. Secrets are redacted before this is set. */
  snippet?: string;
}

export interface DependencyInfo {
  name: string;
  version: string;
  ecosystem: string;
  /** Advisory IDs grouped into this finding (GHSA, CVE, PYSEC, ...). */
  advisories: string[];
  fixedVersions: string[];
}

export interface DataflowStep {
  path: string;
  line: number;
  snippet?: string;
}

/**
 * The single shape every engine is normalized into. Nothing past src/engines/
 * should depend on engine-specific output.
 */
export interface Finding {
  /** Stable fingerprint: survives line moves, changes when the issue changes. */
  id: string;
  category: Category;
  engine: EngineName;
  ruleId: string;
  title: string;
  message: string;
  severity: Severity;
  confidence?: "high" | "medium" | "low";
  location: Location;
  cwe: string[];
  owasp: string[];
  dependency?: DependencyInfo;
  /** Source → sink steps for taint findings. */
  dataflow?: DataflowStep[];
}

export function fingerprint(...parts: string[]): string {
  return createHash("sha256").update(parts.join("\u0000")).digest("hex").slice(0, 32);
}

/**
 * Drop all whitespace so reformatting code (e.g. a formatter wrapping a call
 * across lines) does not change a fingerprint.
 */
export function normalizeCode(code: string): string {
  return code.replace(/\s+/g, "");
}

/**
 * Keep just enough of a secret to recognize it; never store the full value.
 * Short values (passwords, PINs) are fully masked: a 4-char prefix of a
 * 10-char password gives too much away. Long tokens keep their 4-char type
 * prefix (`ghp_`, `AKIA`, `sk-a`) and a fixed-width mask that hides the length.
 */
export function redactSecret(secret: string): string {
  if (secret.length < 16) return "*".repeat(Math.min(secret.length, 8));
  return `${secret.slice(0, 4)}${"*".repeat(12)}`;
}

/** Redact the contents of every string literal ('…', "…", `…`) in a code excerpt. */
export function redactStringLiterals(code: string): string {
  return code.replace(/(["'`])((?:\\.|(?!\1)[^\\\n])*)\1/g, (_, q: string, body: string) => `${q}${redactSecret(body)}${q}`);
}

/**
 * Hash a secret for fingerprinting. Fingerprints may leave the machine (dashboard,
 * PR comments), so a fast hash would let anyone brute-force short secrets offline
 * from a fingerprint. scrypt makes each guess expensive while staying stable
 * across machines.
 */
export function secretDigest(secret: string): string {
  return scryptSync(secret, "vigil/secret-fingerprint/v1", 32, { N: 1 << 14, r: 8, p: 1 }).toString("hex");
}

export function severityAtLeast(s: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER.indexOf(s) <= SEVERITY_ORDER.indexOf(threshold);
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      a.location.path.localeCompare(b.location.path) ||
      a.location.startLine - b.location.startLine,
  );
}

/** Drop exact duplicates (same fingerprint), keeping the first. */
export function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => (seen.has(f.id) ? false : (seen.add(f.id), true)));
}

/** Lower is stronger: confidence first, then whether a source → sink trace backs it. */
function strength(f: Finding): number {
  const c = f.confidence === "high" ? 0 : f.confidence === "medium" ? 1 : f.confidence === "low" ? 2 : 3;
  return c * 2 + (f.dataflow ? 0 : 1);
}

/**
 * When two rules report the same CWE on the same line (a request-taint rule and its
 * pattern-only twin, say), keep only the strongest one; ties keep the first.
 */
export function collapseOverlaps(findings: Finding[]): Finding[] {
  const byLine = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = `${f.location.path}\u0000${f.location.startLine}`;
    byLine.set(key, [...(byLine.get(key) ?? []), f]);
  }
  return findings.filter((f) => {
    const peers = byLine.get(`${f.location.path}\u0000${f.location.startLine}`) ?? [];
    return !peers.some(
      (g, i) =>
        g !== f &&
        g.ruleId !== f.ruleId &&
        g.cwe.some((c) => f.cwe.includes(c)) &&
        (strength(g) < strength(f) || (strength(g) === strength(f) && i < peers.indexOf(f))),
    );
  });
}
