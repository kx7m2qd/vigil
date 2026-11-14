import { execFile } from "node:child_process";
import { isAbsolute, resolve } from "node:path";

/** Added line ranges per file, 1-based and inclusive, keyed by the new path. */
export type AddedLines = Map<string, Array<[number, number]>>;

export interface IndexEntry {
  mode: string;
  oid: string;
  path: string;
}

/** Run git with an argument array (no shell). Returns raw bytes so binary blobs are safe. */
export function git(args: string[], cwd: string): Promise<Buffer> {
  return new Promise((resolvePromise, reject) => {
    execFile(
      "git",
      args,
      { cwd, encoding: "buffer", maxBuffer: 1024 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          const detail = Buffer.isBuffer(stderr) ? stderr.toString("utf8").trim() : "";
          reject(new Error(detail || err.message));
        } else resolvePromise(stdout);
      },
    );
  });
}

function splitNul(buf: Buffer): string[] {
  return buf.toString("utf8").split("\0").filter((s) => s.length > 0);
}

export async function repoRoot(cwd: string): Promise<string> {
  return (await git(["rev-parse", "--show-toplevel"], cwd)).toString("utf8").trim();
}

/** Hook directory; respects core.hooksPath and worktrees. */
export async function hooksDir(cwd: string): Promise<string> {
  const out = (await git(["rev-parse", "--git-path", "hooks"], cwd)).toString("utf8").trim();
  return isAbsolute(out) ? out : resolve(cwd, out);
}

/** Staged paths (added, copied, modified, renamed -> new path), relative to the repo root. */
export async function stagedFiles(root: string): Promise<string[]> {
  const out = await git(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"], root);
  return splitNul(out);
}

/**
 * Files changed in the working tree versus HEAD (added, copied, modified, renamed), plus untracked
 * files that aren't gitignored. Paths are relative to `dir`, limited to it. In a repo with no
 * commits yet, every tracked file counts as changed.
 */
export async function changedFiles(dir: string): Promise<string[]> {
  let tracked: string[];
  try {
    await git(["rev-parse", "--verify", "--quiet", "HEAD"], dir);
    tracked = splitNul(await git(["diff", "HEAD", "--name-only", "-z", "--relative", "--diff-filter=ACMR"], dir));
  } catch {
    tracked = splitNul(await git(["ls-files", "-z"], dir));
  }
  const untracked = splitNul(await git(["ls-files", "-z", "--others", "--exclude-standard"], dir));
  return [...new Set([...tracked, ...untracked])].sort();
}

/** Mode and blob id of each path as staged in the index (stage 0 only). */
export async function indexEntries(root: string, paths: string[]): Promise<Map<string, IndexEntry>> {
  const result = new Map<string, IndexEntry>();
  if (paths.length === 0) return result;
  const out = await git(["--literal-pathspecs", "ls-files", "-s", "-z", "--", ...paths], root);
  for (const rec of splitNul(out)) {
    // "<mode> <oid> <stage>\t<path>"
    const tab = rec.indexOf("\t");
    if (tab < 0) continue;
    const [mode, oid, stage] = rec.slice(0, tab).split(" ");
    if (stage !== "0" || !mode || !oid) continue;
    const path = rec.slice(tab + 1);
    result.set(path, { mode, oid, path });
  }
  return result;
}

export function readIndexBlob(root: string, oid: string): Promise<Buffer> {
  return git(["cat-file", "blob", oid], root);
}

export async function stagedDiff(root: string): Promise<string> {
  const out = await git(
    ["-c", "core.quotepath=off", "diff", "--cached", "-U0", "--no-color", "--no-ext-diff"],
    root,
  );
  return out.toString("utf8");
}

/** True if the first 8 KB contains a NUL byte. */
export function isBinary(buf: Buffer): boolean {
  return buf.subarray(0, 8192).includes(0);
}

function unquoteGitPath(s: string): string {
  if (!(s.length >= 2 && s.startsWith('"') && s.endsWith('"'))) return s;
  const body = s.slice(1, -1);
  const bytes: number[] = [];
  const simple: Record<string, number> = { n: 10, t: 9, r: 13, a: 7, b: 8, f: 12, v: 11, "\\": 92, '"': 34 };
  for (let i = 0; i < body.length; i++) {
    const ch = body[i]!;
    if (ch !== "\\") {
      bytes.push(...Buffer.from(ch, "utf8"));
      continue;
    }
    const next = body[i + 1] ?? "";
    if (/[0-7]/.test(next)) {
      const oct = /^[0-7]{1,3}/.exec(body.slice(i + 1))![0];
      bytes.push(parseInt(oct, 8));
      i += oct.length;
    } else {
      bytes.push(simple[next] ?? next.charCodeAt(0));
      i += 1;
    }
  }
  return Buffer.from(bytes).toString("utf8");
}

/**
 * Parse `git diff -U0` output into the added line ranges of each file.
 * Pure: takes the diff text only.
 */
export function addedLines(diffText: string): AddedLines {
  const result: AddedLines = new Map();
  let current: string | undefined;
  let oldLeft = 0;
  let newLeft = 0;

  for (const line of diffText.split("\n")) {
    if (oldLeft > 0 || newLeft > 0) {
      // Inside a hunk: consume by counts so content like "+++ x" is not mistaken for a header.
      if (line.startsWith("+")) newLeft--;
      else if (line.startsWith("-")) oldLeft--;
      else if (!line.startsWith("\\")) {
        oldLeft--;
        newLeft--;
      }
      continue;
    }
    if (line.startsWith("+++ ")) {
      // Names with spaces get a trailing tab appended by git.
      const name = unquoteGitPath(line.slice(4).replace(/\t.*$/, ""));
      current = name === "/dev/null" ? undefined : name.replace(/^b\//, "");
      continue;
    }
    if (line.startsWith("diff --git ")) {
      current = undefined;
      continue;
    }
    const m = /^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (m && current) {
      oldLeft = m[1] === undefined ? 1 : Number(m[1]);
      const start = Number(m[2]);
      const count = m[3] === undefined ? 1 : Number(m[3]);
      newLeft = count;
      if (count > 0) {
        const list = result.get(current) ?? [];
        list.push([start, start + count - 1]);
        result.set(current, list);
      }
    }
  }
  return result;
}
