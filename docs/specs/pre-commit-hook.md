# Spec: pre-commit hook (`vigil hook`)

## Goal
Stop secrets and high-severity code issues from being committed, fast enough (< 3 s on a typical
commit with warm engines) that nobody reaches for `--no-verify`.

## Commands
- `vigil hook install [--force]` writes the pre-commit hook into the repo that contains the cwd.
- `vigil hook uninstall` removes it, but only if Vigil wrote it.
- `vigil hook run [--fail-on <severity|none>]` is what the hook calls. You can also run it by hand.

## `hook run`: what gets scanned
1. **Scan the index, not the working tree.** With partial staging (`git add -p`), the working tree
   can differ from what will be committed. Staged blobs are the truth.
2. Staged files: `git diff --cached --name-only -z --diff-filter=ACMR`. NUL-separated, so spaces and
   unicode in names are safe. Deleted files are skipped.
3. Each staged path is written from `git show :<path>` (or `git cat-file blob <oid>` from
   `git ls-files -s -z`) into a fresh `mkdtemp` dir (0700). Skip submodules (mode `160000`), symlinks
   (`120000`), and binary blobs (a NUL byte in the first 8 KB). The repo's `.vigilignore` is also
   copied from the index (not the working tree) when it is present in the index.
4. Run `scan()` on the temp dir with engines `opengrep` + `gitleaks` only. osv-scanner is skipped:
   it is slow and needs the network. Dependency checks belong in CI (`vigil scan`). Use
   `autoInstall: false`. The hook never downloads during a commit.
5. **Only findings on added lines count.** Parse `git diff --cached -U0 --no-color --no-ext-diff`
   hunk headers (`@@ -a,b +c,d @@`) into added line ranges per file. Keep a finding if
   `[startLine, endLine ?? startLine]` intersects an added range. Pre-existing issues in a touched
   file are not shown, so they don't block unrelated work. The count is printed as one line:
   "N existing findings in changed files not shown; run `vigil scan`".
6. The temp dir is always removed (`finally`). Source never leaves the machine.

## Blocking
- Exit 1 (block) if any kept finding is a **secret** (any severity), or any kept finding is at least
  `--fail-on` (default `high`).
- Exit 0 otherwise, including when nothing is staged.
- **Engine missing or failed → exit 2 (block, fail closed)** with:
  "vigil: <engine> unavailable. Run `vigil engines install`, or bypass once with `git commit --no-verify`."
- Output: the existing text reporter (`toText`), colored when stderr is a TTY. Output goes to
  **stderr** (git shows hook stderr). Secrets are already redacted by the normalizers.
  Never print raw blob content.
- Footer when blocking: "Commit blocked by vigil. Fix the findings, or bypass once with
  `git commit --no-verify`."

## `hook install`
- Hook dir: `git rev-parse --git-path hooks`. This respects `core.hooksPath` and worktrees.
- Script (POSIX sh, mode 0755) carrying a marker line `# vigil-managed-hook`:
  ```sh
  #!/bin/sh
  # vigil-managed-hook
  exec "<absolute node path>" "<absolute path to dist/cli.js>" hook run "$@"
  ```
  The CLI path is resolved from `import.meta.url`: `dist/cli.js` when running built code, and
  `<pkg>/dist/cli.js` when running from `src/` via tsx. If that file does not exist, fail with
  "run `npm run build` first". Paths are shell-quoted (single quotes, `'` escaped).
- An existing `pre-commit` without the marker: refuse (exit 2) and say so, unless `--force` is
  given. `--force` renames the old hook to `pre-commit.vigil-backup` first.
- An existing Vigil hook: overwrite it (idempotent).
- Not inside a git repo: exit 2 with a clear message.

## `hook uninstall`
- Remove `pre-commit` only if it has the marker. Restore `pre-commit.vigil-backup` if present.
- No hook, or a foreign hook: print what was found and exit 0 without touching it.

## Edge cases
- Initial commit (no `HEAD`): `git diff --cached` still works against the empty tree.
- Renames (`R`): scan the new path. Only added lines count.
- Merge commits: same rules (the staged diff against HEAD).
- Nothing staged, or only deletions: exit 0 immediately without starting engines.
- Huge staged sets: no special case in v1. Measure first.
- `.gitleaksignore` staged in the repo root: already handled by `runGitleaks` (ignored, with a warning).
- Git commands run via `node:child_process` `execFile`/`spawn` with no shell and a list of args.

## Code layout
- `src/hook/git.ts`: `stagedFiles()`, `addedLines(diffText)` (pure parser), `readIndexBlob()`,
  `hooksDir()`.
- `src/hook/run.ts`: materialize staged blobs, run `scan()`, filter, decide the exit code.
- `src/hook/install.ts`: `install({ force })`, `uninstall()`, `hookScript(node, cli)` (pure).
- `src/cli.ts`: add the `hook` command and help text.

## Tests (vitest, `test/hook.test.ts`)
- `addedLines`: multi-hunk, `+c` without a count (= 1 line), `+c,0` (pure deletion, no lines),
  new-file hunks, filenames with spaces (from `diff --git` / `+++ b/` headers).
- Intersection filter: a finding before, inside, spanning, or after an added range.
- `hookScript`: has the marker, quoting survives paths with spaces and `'`.
- Install/uninstall in a temp `git init` repo: fresh install, idempotent reinstall, refuses a foreign
  hook, `--force` backs it up, uninstall restores the backup, respects `core.hooksPath`.
- End-to-end in a temp repo (skip if gitleaks is not installed): stage a file with a fake AWS key on
  an added line → `hook run` exits 1. Stage a clean change in a file that already holds a committed
  secret → exits 0. Partial staging: the secret is only in the working tree, not the index → exits 0.

## Done
- `npm run check` and `npm run bench` pass. README/help text documents `vigil hook`.
- Measured: `hook run` wall time on a 1-file commit in this repo, recorded in the PR/commit message.
