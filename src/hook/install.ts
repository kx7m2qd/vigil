import { access, chmod, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { hooksDir } from "./git.js";

export const HOOK_MARKER = "# vigil-managed-hook";
const BACKUP = "pre-commit.vigil-backup";

export interface HookResult {
  code: number;
  message: string;
}

function shQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** The pre-commit script. Pure. */
export function hookScript(node: string, cli: string): string {
  return `#!/bin/sh\n${HOOK_MARKER}\nexec ${shQuote(node)} ${shQuote(cli)} hook run "$@"\n`;
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function readIfExists(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, "utf8");
  } catch {
    return undefined;
  }
}

/** dist/cli.js of this package, whether running built code or src/ via tsx. */
function cliPath(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "dist", "cli.js");
}

/** `cli` overrides the dist/cli.js path the hook runs (tests use it so they don't need a build). */
export async function install(opts: { force?: boolean; cwd?: string; cli?: string } = {}): Promise<HookResult> {
  const cwd = opts.cwd ?? process.cwd();
  let dir: string;
  try {
    dir = await hooksDir(cwd);
  } catch {
    return { code: 2, message: "not inside a git repository" };
  }
  const cli = opts.cli ?? cliPath();
  if (!(await exists(cli))) return { code: 2, message: `${cli} not found: run \`npm run build\` first` };

  const target = join(dir, "pre-commit");
  const existing = await readIfExists(target);
  let note = "";
  if (existing !== undefined && !existing.includes(HOOK_MARKER)) {
    if (!opts.force) {
      return {
        code: 2,
        message: `${target} already exists and was not written by vigil. Re-run with --force to back it up to ${BACKUP}.`,
      };
    }
    const backup = join(dir, BACKUP);
    if (await exists(backup)) {
      return { code: 2, message: `${backup} already exists; move it aside before using --force.` };
    }
    await rename(target, backup);
    note = ` (previous hook saved as ${BACKUP})`;
  }
  await mkdir(dir, { recursive: true });
  await writeFile(target, hookScript(process.execPath, cli), { mode: 0o755 });
  await chmod(target, 0o755);
  return { code: 0, message: `installed ${target}${note}` };
}

export async function uninstall(opts: { cwd?: string } = {}): Promise<HookResult> {
  const cwd = opts.cwd ?? process.cwd();
  let dir: string;
  try {
    dir = await hooksDir(cwd);
  } catch {
    return { code: 2, message: "not inside a git repository" };
  }
  const target = join(dir, "pre-commit");
  const existing = await readIfExists(target);
  if (existing === undefined) return { code: 0, message: `no pre-commit hook found in ${dir}` };
  if (!existing.includes(HOOK_MARKER)) {
    return { code: 0, message: `${target} was not written by vigil; left untouched` };
  }
  await rm(target);
  const backup = join(dir, BACKUP);
  if (await exists(backup)) {
    await rename(backup, target);
    return { code: 0, message: `removed vigil hook and restored ${target} from ${BACKUP}` };
  }
  return { code: 0, message: `removed ${target}` };
}
