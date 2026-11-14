import { execFile } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import type { Finding } from "../src/core/finding.js";
import { isInstalled } from "../src/engines/install.js";
import { addedLines } from "../src/hook/git.js";
import { HOOK_MARKER, hookScript, install as installHook, uninstall } from "../src/hook/install.js";
import { filterToAdded, hookRun } from "../src/hook/run.js";

const exec = promisify(execFile);
const IDENT = ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"];

async function git(cwd: string, ...args: string[]): Promise<string> {
  const { stdout } = await exec("git", [...IDENT, ...args], { cwd });
  return stdout;
}

const dirs: string[] = [];
async function tempRepo(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "vigil-hook-test-"));
  dirs.push(dir);
  await git(dir, "init", "-q");
  return dir;
}
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

function finding(path: string, startLine: number, endLine?: number): Finding {
  return {
    id: `${path}:${startLine}`,
    category: "code",
    engine: "opengrep",
    ruleId: "x",
    title: "t",
    message: "m",
    severity: "high",
    location: { path, startLine, endLine },
    cwe: [],
    owasp: [],
  };
}

describe("addedLines", () => {
  it("parses multiple hunks", () => {
    const diff = [
      "diff --git a/a.js b/a.js",
      "index 111..222 100644",
      "--- a/a.js",
      "+++ b/a.js",
      "@@ -3,0 +4,2 @@ ctx",
      "+x",
      "+y",
      "@@ -10 +12,3 @@",
      "-old",
      "+n1",
      "+n2",
      "+n3",
    ].join("\n");
    expect(addedLines(diff).get("a.js")).toEqual([
      [4, 5],
      [12, 14],
    ]);
  });

  it("treats +c without a count as one line", () => {
    const diff = "+++ b/a.js\n@@ -5 +5 @@\n-a\n+b\n";
    expect(addedLines(diff).get("a.js")).toEqual([[5, 5]]);
  });

  it("ignores pure deletions (+c,0)", () => {
    const diff = "+++ b/a.js\n@@ -5,2 +4,0 @@\n-a\n-b\n";
    expect(addedLines(diff).has("a.js")).toBe(false);
  });

  it("handles new files", () => {
    const diff = [
      "diff --git a/n.py b/n.py",
      "new file mode 100644",
      "--- /dev/null",
      "+++ b/n.py",
      "@@ -0,0 +1,3 @@",
      "+a",
      "+b",
      "+c",
    ].join("\n");
    expect(addedLines(diff).get("n.py")).toEqual([[1, 3]]);
  });

  it("handles filenames with spaces and quoted names", () => {
    const diff = [
      "diff --git a/my file.js b/my file.js",
      "--- a/my file.js\t",
      "+++ b/my file.js\t",
      "@@ -1 +1 @@",
      "-a",
      "+b",
      "diff --git a/q.js b/q.js",
      '--- "a/t\\tab.js"',
      '+++ "b/t\\tab.js"',
      "@@ -2,0 +3 @@",
      "+z",
    ].join("\n");
    const res = addedLines(diff);
    expect(res.get("my file.js")).toEqual([[1, 1]]);
    expect(res.get("t\tab.js")).toEqual([[3, 3]]);
  });

  it("does not mistake added content that looks like a header", () => {
    const diff = "+++ b/a.js\n@@ -0,0 +1,2 @@\n+++ b/evil.js\n+@@ -1 +9 @@\n";
    const res = addedLines(diff);
    expect([...res.keys()]).toEqual(["a.js"]);
    expect(res.get("a.js")).toEqual([[1, 2]]);
  });
});

describe("filterToAdded", () => {
  const added = new Map([["a.js", [[10, 20] as [number, number]]]]);

  it("drops findings before and after, keeps inside and spanning", () => {
    const out = filterToAdded(
      [
        finding("a.js", 5), // before
        finding("a.js", 9, 9),
        finding("a.js", 10), // edge
        finding("a.js", 15), // inside
        finding("a.js", 20), // edge
        finding("a.js", 8, 12), // overlaps start
        finding("a.js", 5, 30), // spanning
        finding("a.js", 21), // after
        finding("b.js", 15), // other file
      ],
      added,
    );
    expect(out.map((f) => f.id)).toEqual(["a.js:10", "a.js:15", "a.js:20", "a.js:8", "a.js:5"]);
  });
});

describe("hookScript", () => {
  it("has the marker and shebang", () => {
    const s = hookScript("/usr/bin/node", "/x/dist/cli.js");
    expect(s.startsWith("#!/bin/sh\n")).toBe(true);
    expect(s).toContain(HOOK_MARKER);
    expect(s).toContain(`exec '/usr/bin/node' '/x/dist/cli.js' hook run "$@"`);
  });

  it("survives spaces and single quotes in paths when run by sh", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vigil-q-"));
    dirs.push(dir);
    const weird = join(dir, "it's a dir");
    await mkdir(weird);
    const fakeNode = join(weird, "node'x");
    await writeFile(fakeNode, '#!/bin/sh\necho "$@"\n');
    await chmod(fakeNode, 0o755);
    const hook = join(dir, "hook.sh");
    await writeFile(hook, hookScript(fakeNode, join(weird, "cli file.js")));
    await chmod(hook, 0o755);
    const { stdout } = await exec(hook, ["arg"]);
    expect(stdout.trim()).toBe(`${join(weird, "cli file.js")} hook run arg`);
  });
});

describe("install / uninstall", () => {
  const hookPath = (repo: string) => join(repo, ".git", "hooks", "pre-commit");
  // A stand-in for dist/cli.js, so these tests don't depend on `npm run build` having run.
  const fakeCli = join(tmpdir(), `vigil-fake-cli-${process.pid}.js`);
  beforeAll(() => writeFile(fakeCli, ""));
  afterAll(() => rm(fakeCli, { force: true }));
  const install = (o: { cwd: string; force?: boolean }) => installHook({ ...o, cli: fakeCli });

  it("installs, is idempotent, and is executable", async () => {
    const repo = await tempRepo();
    expect((await install({ cwd: repo })).code).toBe(0);
    const first = await readFile(hookPath(repo), "utf8");
    expect(first).toContain(HOOK_MARKER);
    expect((await stat(hookPath(repo))).mode & 0o111).not.toBe(0);
    expect((await install({ cwd: repo })).code).toBe(0);
    expect(await readFile(hookPath(repo), "utf8")).toBe(first);
  });

  it("refuses a foreign hook, and --force backs it up", async () => {
    const repo = await tempRepo();
    await writeFile(hookPath(repo), "#!/bin/sh\necho mine\n", { mode: 0o755 });
    const refused = await install({ cwd: repo });
    expect(refused.code).toBe(2);
    expect(await readFile(hookPath(repo), "utf8")).toContain("echo mine");

    expect((await install({ cwd: repo, force: true })).code).toBe(0);
    expect(await readFile(hookPath(repo), "utf8")).toContain(HOOK_MARKER);
    expect(await readFile(hookPath(repo) + ".vigil-backup", "utf8")).toContain("echo mine");
  });

  it("uninstall restores the backup, leaves foreign hooks, and tolerates no hook", async () => {
    const repo = await tempRepo();
    expect((await uninstall({ cwd: repo })).code).toBe(0);

    await writeFile(hookPath(repo), "#!/bin/sh\necho mine\n", { mode: 0o755 });
    expect((await uninstall({ cwd: repo })).code).toBe(0);
    expect(await readFile(hookPath(repo), "utf8")).toContain("echo mine");

    await install({ cwd: repo, force: true });
    expect((await uninstall({ cwd: repo })).code).toBe(0);
    expect(await readFile(hookPath(repo), "utf8")).toContain("echo mine");
    await expect(stat(hookPath(repo) + ".vigil-backup")).rejects.toThrow();
  });

  it("respects core.hooksPath", async () => {
    const repo = await tempRepo();
    await git(repo, "config", "core.hooksPath", ".githooks");
    expect((await install({ cwd: repo })).code).toBe(0);
    expect(await readFile(join(repo, ".githooks", "pre-commit"), "utf8").catch(() => "")).toContain(HOOK_MARKER);
  });

  it("fails outside a git repo", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vigil-nogit-"));
    dirs.push(dir);
    const res = await install({ cwd: dir });
    expect(res.code).toBe(2);
    expect(res.message).toMatch(/git repository/);
  });
});

const enginesReady = (await isInstalled("gitleaks")) && (await isInstalled("opengrep"));

describe("hook run (end to end)", () => {
  // Built at runtime so this file holds no literal secret (the repo self-scans).
  const secretLine = () => `const awsKey = "${"AKIA" + "ZQXWVTRPLMNKJHGF"}";\n`;
  const opts = { failOn: "high" as const, color: false };

  it("exits 0 when nothing is staged", async () => {
    const repo = await tempRepo();
    expect(await hookRun({ ...opts, cwd: repo })).toEqual({ code: 0, output: "" });
  });

  it.skipIf(!enginesReady)("blocks a secret on an added line", async () => {
    const repo = await tempRepo();
    await writeFile(join(repo, "app.js"), "const a = 1;\n" + secretLine());
    await git(repo, "add", "app.js");
    const res = await hookRun({ ...opts, cwd: repo });
    expect(res.code).toBe(1);
    expect(res.output).toContain("Commit blocked by vigil");
    expect(res.output).not.toContain("ZQXWVTRPLMNKJHGF");
  }, 60_000);

  it.skipIf(!enginesReady)("ignores a committed secret when the change is clean", async () => {
    const repo = await tempRepo();
    await writeFile(join(repo, "app.js"), secretLine() + "const a = 1;\n");
    await git(repo, "add", "app.js");
    await git(repo, "commit", "-q", "-m", "init");
    await writeFile(join(repo, "app.js"), secretLine() + "const a = 2;\n");
    await git(repo, "add", "app.js");
    const res = await hookRun({ ...opts, cwd: repo });
    expect(res.code).toBe(0);
    expect(res.output).toContain("existing findings in changed files not shown");
  }, 60_000);

  it.skipIf(!enginesReady)("scans the index, not the working tree", async () => {
    const repo = await tempRepo();
    await writeFile(join(repo, "app.js"), "const a = 1;\n");
    await git(repo, "add", "app.js");
    await writeFile(join(repo, "app.js"), "const a = 1;\n" + secretLine());
    const res = await hookRun({ ...opts, cwd: repo });
    expect(res.code).toBe(0);
  }, 60_000);
});
