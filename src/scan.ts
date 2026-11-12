import { resolve } from "node:path";
import { dedupe, sortFindings, type EngineName, type Finding } from "./core/finding.js";
import { DEFAULT_IGNORES, isIgnored, loadIgnorePatterns } from "./core/ignore.js";
import { runGitleaks } from "./engines/gitleaks.js";
import { overrideVar, resolveEngine } from "./engines/install.js";
import { runOpengrep } from "./engines/opengrep.js";
import { runOsv } from "./engines/osv.js";
import type { EngineOutput } from "./engines/types.js";

export const ALL_ENGINES: EngineName[] = ["opengrep", "osv-scanner", "gitleaks"];

export interface ScanOptions {
  engines?: EngineName[];
  autoInstall?: boolean;
}

export interface EngineStatus {
  engine: EngineName;
  ok: boolean;
  findings: number;
  ms: number;
  error?: string;
}

export interface ScanResult {
  root: string;
  findings: Finding[];
  /**
   * Patterns from the repo's own .vigilignore. Surfaced in every report: the repo
   * is untrusted, and a change here can hide findings.
   */
  ignores: string[];
  warnings: string[];
  engines: EngineStatus[];
}

export async function scan(target: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const root = resolve(target);
  const ignores = await loadIgnorePatterns(root);
  const engines = opts.engines ?? ALL_ENGINES;
  const autoInstall = opts.autoInstall ?? true;

  const runners: Record<EngineName, (bin: string) => Promise<EngineOutput>> = {
    opengrep: (bin) => runOpengrep(bin, root, ignores),
    "osv-scanner": (bin) => runOsv(bin, root),
    gitleaks: (bin) => runGitleaks(bin, root),
  };

  // Engines run in parallel; one failing engine must not hide the others' results.
  const outcomes = await Promise.all(
    engines.map(async (engine) => {
      const started = Date.now();
      try {
        const bin = await resolveEngine(engine, { autoInstall });
        const out = await runners[engine](bin);
        return { engine, out, ms: Date.now() - started };
      } catch (e) {
        return { engine, error: e instanceof Error ? e.message : String(e), ms: Date.now() - started };
      }
    }),
  );

  const findings: Finding[] = [];
  const warnings: string[] = [];
  for (const engine of engines) {
    const v = overrideVar(engine);
    if (process.env[v]) warnings.push(`${engine}: using ${v}=${process.env[v]}, which is not checksum-verified`);
  }
  const statuses: EngineStatus[] = [];
  for (const o of outcomes) {
    if ("error" in o) {
      statuses.push({ engine: o.engine, ok: false, findings: 0, ms: o.ms, error: o.error });
      warnings.push(`${o.engine} failed: ${o.error}`);
      continue;
    }
    const kept = o.out.findings.filter((f) => !isIgnored(f.location.path, ignores));
    findings.push(...kept);
    warnings.push(...o.out.warnings);
    statuses.push({ engine: o.engine, ok: true, findings: kept.length, ms: o.ms });
  }

  return {
    root,
    findings: sortFindings(dedupe(findings)),
    ignores: ignores.slice(DEFAULT_IGNORES.length),
    warnings,
    engines: statuses,
  };
}
