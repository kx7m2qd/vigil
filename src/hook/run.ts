import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { severityAtLeast, type Finding, type Severity } from "../core/finding.js";
import { toText } from "../report/text.js";
import { scan } from "../scan.js";
import {
  addedLines,
  indexEntries,
  isBinary,
  readIndexBlob,
  repoRoot,
  stagedDiff,
  stagedFiles,
  type AddedLines,
} from "./git.js";

export interface HookRunResult {
  code: number;
  /** Text for stderr. */
  output: string;
}

/** Keep findings whose line span intersects an added range of their file. Pure. */
export function filterToAdded(findings: Finding[], added: AddedLines): Finding[] {
  return findings.filter((f) => {
    const ranges = added.get(f.location.path);
    if (!ranges) return false;
    const start = f.location.startLine;
    const end = f.location.endLine ?? start;
    return ranges.some(([a, b]) => start <= b && end >= a);
  });
}

/** Whether the kept findings should block the commit. Pure. */
export function shouldBlock(findings: Finding[], failOn: Severity | "none"): boolean {
  return findings.some(
    (f) => f.category === "secret" || (failOn !== "none" && severityAtLeast(f.severity, failOn)),
  );
}

const SKIP_MODES = new Set(["160000", "120000"]);

/** Write staged blobs (and the staged .vigilignore) into dest. Returns how many staged files were written. */
async function materialize(root: string, dest: string, paths: string[]): Promise<number> {
  const wanted = [...new Set([...paths, ".vigilignore"])];
  const entries = await indexEntries(root, wanted);
  let written = 0;
  for (const rel of wanted) {
    const entry = entries.get(rel);
    if (!entry || SKIP_MODES.has(entry.mode)) continue;
    const blob = await readIndexBlob(root, entry.oid);
    if (isBinary(blob)) continue;
    const out = resolve(dest, rel);
    if (!out.startsWith(dest + sep)) continue;
    await mkdir(dirname(out), { recursive: true });
    await writeFile(out, blob);
    if (paths.includes(rel)) written++;
  }
  return written;
}

export async function hookRun(opts: {
  failOn: Severity | "none";
  color: boolean;
  cwd?: string;
}): Promise<HookRunResult> {
  const root = await repoRoot(opts.cwd ?? process.cwd());
  const staged = await stagedFiles(root);
  if (staged.length === 0) return { code: 0, output: "" };

  const tmp = await mkdtemp(join(tmpdir(), "vigil-hook-")); // mode 0700
  try {
    const dest = resolve(tmp);
    if ((await materialize(root, dest, staged)) === 0) return { code: 0, output: "" };

    const added = addedLines(await stagedDiff(root));
    const result = await scan(dest, { engines: ["opengrep", "gitleaks"], autoInstall: false });

    const failed = result.engines.find((e) => !e.ok);
    if (failed) {
      return {
        code: 2,
        output: `vigil: ${failed.engine} unavailable. Run \`vigil engines install\`, or bypass once with \`git commit --no-verify\`.\n`,
      };
    }

    const kept = filterToAdded(result.findings, added);
    const hidden = result.findings.length - kept.length;
    const block = shouldBlock(kept, opts.failOn);
    const lines: string[] = [];
    if (kept.length > 0) lines.push(toText({ ...result, findings: kept }, { color: opts.color }));
    if (hidden > 0) lines.push(`${hidden} existing findings in changed files not shown; run \`vigil scan\``);
    if (block) {
      lines.push("Commit blocked by vigil. Fix the findings, or bypass once with `git commit --no-verify`.");
    }
    return { code: block ? 1 : 0, output: lines.length ? lines.join("\n") + "\n" : "" };
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}
