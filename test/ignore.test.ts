import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DEFAULT_IGNORES, isIgnored, loadIgnorePatterns } from "../src/core/ignore.js";

describe("isIgnored", () => {
  const patterns = [...DEFAULT_IGNORES, "bench/cases/", "fixtures", "src/generated/api.ts"];

  it("matches bare directory names at any depth", () => {
    expect(isIgnored("node_modules/x/index.js", patterns)).toBe(true);
    expect(isIgnored("packages/web/node_modules/x/index.js", patterns)).toBe(true);
    expect(isIgnored("test/fixtures/vuln.js", patterns)).toBe(true);
  });

  it("matches multi-segment patterns only as a root prefix", () => {
    expect(isIgnored("bench/cases/app.js", patterns)).toBe(true);
    expect(isIgnored("other/bench/cases/app.js", patterns)).toBe(false);
    expect(isIgnored("src/generated/api.ts", patterns)).toBe(true);
  });

  it("does not match partial names", () => {
    expect(isIgnored("src/distance.js", patterns)).toBe(false);
    expect(isIgnored("src/builder/index.js", patterns)).toBe(false);
  });

  it("normalizes ./ and backslashes", () => {
    expect(isIgnored("./dist/cli.js", patterns)).toBe(true);
    expect(isIgnored("bench\\cases\\app.js", patterns)).toBe(true);
  });
});

describe("loadIgnorePatterns", () => {
  it("reads .vigilignore, skipping comments and blanks", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vigil-ignore-"));
    await writeFile(join(dir, ".vigilignore"), "# comment\n\nrules/\n  fixtures  \n");
    const patterns = await loadIgnorePatterns(dir);
    expect(patterns).toEqual([...DEFAULT_IGNORES, "rules/", "fixtures"]);
  });

  it("falls back to defaults without a file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vigil-ignore-"));
    expect(await loadIgnorePatterns(dir)).toEqual(DEFAULT_IGNORES);
  });

  it("the repo's own .vigilignore excludes the intentionally vulnerable folders", async () => {
    const patterns = await loadIgnorePatterns(process.cwd());
    for (const p of ["rules/x.js", "bench/cases/x.js", "test/fixtures/x.js"]) {
      expect(isIgnored(p, patterns)).toBe(true);
    }
  });
});
