import { cp, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { fingerprint, redactSecret, secretDigest, type Finding } from "../core/finding.js";
import { toRelative } from "./paths.js";
import { run } from "./run.js";
import type { EngineOutput } from "./types.js";

export interface GitleaksLeak {
  RuleID: string;
  Description: string;
  StartLine: number;
  EndLine: number;
  StartColumn: number;
  Match: string;
  Secret: string;
  File: string;
}

const CONFIG_DIR = fileURLToPath(new URL("../../config", import.meta.url));

/** Generic heuristics are noisier than provider-specific token formats. */
const LOWER_CONFIDENCE_RULES = new Set(["generic-api-key"]);

export function normalizeGitleaks(root: string, leaks: GitleaksLeak[]): Finding[] {
  return leaks.map((l) => {
    const path = toRelative(root, l.File);
    const secretHash = secretDigest(l.Secret);
    const redacted = redactSecret(l.Secret);
    const generic = LOWER_CONFIDENCE_RULES.has(l.RuleID);
    return {
      id: fingerprint("gitleaks", l.RuleID, path, secretHash),
      category: "secret",
      engine: "gitleaks",
      ruleId: l.RuleID,
      title: `Hardcoded secret (${l.RuleID})`,
      message:
        `${l.Description} Value: ${redacted}. Revoke and rotate this credential, then load it from ` +
        `an environment variable or a secrets manager. Removing it from the file is not enough if it was committed.`,
      severity: generic ? "medium" : "high",
      confidence: generic ? "medium" : "high",
      location: {
        path,
        startLine: l.StartLine,
        endLine: l.EndLine,
        startColumn: l.StartColumn,
        snippet: l.Match.split(l.Secret).join(redacted),
      },
      cwe: ["CWE-798"],
      owasp: ["A07:2021 - Identification and Authentication Failures"],
    } satisfies Finding;
  });
}

/**
 * Gitleaks always honours `<source>/.gitleaksignore`, whatever `--gitleaks-ignore-path` says.
 * Only the root one is read (nested ones are not), so when it exists we scan a copy without it.
 * Matched case-insensitively because macOS and Windows filesystems usually are.
 */
async function rootIgnoreFiles(root: string): Promise<string[]> {
  return (await readdir(root)).filter((name) => name.toLowerCase() === ".gitleaksignore");
}

export async function runGitleaks(bin: string, root: string): Promise<EngineOutput> {
  const warnings: string[] = [];
  const ignoreFiles = await rootIgnoreFiles(root);
  let cwd = root;
  let copy: string | undefined;
  if (ignoreFiles.length > 0) {
    warnings.push(`gitleaks: ignored the repository's ${ignoreFiles.join(", ")}; a scanned repo cannot allowlist its own secrets`);
    copy = await mkdtemp(join(tmpdir(), "vigil-gitleaks-"));
    const skip = new Set(ignoreFiles.map((name) => join(root, name)));
    await cp(root, copy, { recursive: true, verbatimSymlinks: true, filter: (src) => !skip.has(src) });
    cwd = copy;
  }
  try {
    const res = await run(
      bin,
      [
        "dir",
        "--report-format=json",
        "--report-path=-",
        "--no-banner",
        "--exit-code=0",
        "--log-level=error",
        // The scanned repo must not be able to allowlist its own secrets: use our
        // config, not its .gitleaks.toml / .gitleaksignore / `gitleaks:allow` comments.
        `--config=${CONFIG_DIR}/gitleaks.toml`,
        `--gitleaks-ignore-path=${CONFIG_DIR}`,
        "--ignore-gitleaks-allow",
        "--",
        ".",
      ],
      { cwd },
    );
    if (res.code !== 0) throw new Error(`gitleaks exited ${res.code}: ${res.stderr.trim().slice(0, 500)}`);
    const leaks = JSON.parse(res.stdout || "[]") as GitleaksLeak[];
    // Paths are relative to cwd (".") so they map onto the real root unchanged.
    return { findings: normalizeGitleaks(root, leaks), warnings };
  } finally {
    if (copy) await rm(copy, { recursive: true, force: true });
  }
}
