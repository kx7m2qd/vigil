import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DEFAULT_IGNORES } from "../src/core/ignore.js";
import { normalizeOsv } from "../src/engines/osv.js";
import { runPkgrisk } from "../src/engines/pkgrisk/index.js";
import {
  parseNpmrc,
  parsePackageJson,
  parsePackageLock,
  parsePyproject,
  parseRequirements,
} from "../src/engines/pkgrisk/manifests.js";
import { Registry, type FetchLike } from "../src/engines/pkgrisk/registry.js";
import { damerauLevenshtein, loadTyposquatData, PopularIndex } from "../src/engines/pkgrisk/typosquat.js";
import { scan } from "../src/scan.js";

const NOW = Date.parse("2026-11-12T12:00:00Z");
const daysAgo = (d: number) => new Date(NOW - d * 86_400_000).toISOString();
const hoursAgo = (h: number) => new Date(NOW - h * 3_600_000).toISOString();

const dirs: string[] = [];
async function project(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "vigil-pkgrisk-"));
  dirs.push(dir);
  for (const [name, body] of Object.entries(files)) {
    await mkdir(join(dir, name, ".."), { recursive: true });
    await writeFile(join(dir, name), body);
  }
  return dir;
}
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

const npmDoc = (created: string, versions: Record<string, string> = {}, latest = "1.0.0") => ({
  "dist-tags": { latest },
  time: { created, modified: created, ...versions },
});
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

/** A fake registry: url → response factory. Records every URL requested. */
function fakeFetch(routes: Record<string, () => Response>): { fetch: FetchLike; calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    fetch: async (url) => {
      calls.push(url);
      const r = routes[url];
      return r ? r() : json({}, 404);
    },
  };
}

describe("parsers", () => {
  it("package.json: all dependency sections with line numbers, skipping non-registry specs", () => {
    const text = `{
  "name": "x",
  "dependencies": {
    "express": "^4.0.0",
    "local": "file:../local",
    "forked": "github:me/forked",
    "aliased": "npm:real-pkg@^1.0.0"
  },
  "devDependencies": {
    "vitest": "1.0.0",
    "ws": "workspace:*"
  },
  "optionalDependencies": {
    "fsevents": "2.3.3"
  }
}`;
    const refs = parsePackageJson(text, "package.json");
    expect(refs.map((r) => [r.name, r.line])).toEqual([
      ["express", 4],
      ["real-pkg", 7],
      ["vitest", 10],
      ["fsevents", 14],
    ]);
    expect(refs.every((r) => r.direct && r.ecosystem === "npm")).toBe(true);
  });

  it("package-lock v3: nested node_modules, install scripts, direct vs transitive, non-registry entries", () => {
    const lock = JSON.stringify(
      {
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { a: "^1" }, devDependencies: { esbuild: "^0.2" } },
          "node_modules/a": { version: "1.0.0", resolved: "https://registry.npmjs.org/a/-/a-1.0.0.tgz" },
          "node_modules/a/node_modules/b": { version: "2.0.0", resolved: "https://registry.npmjs.org/b/-/b-2.0.0.tgz" },
          "node_modules/@s/c": { version: "3.0.0", resolved: "https://registry.npmjs.org/@s/c/-/c-3.0.0.tgz" },
          "node_modules/esbuild": { version: "0.2.0", hasInstallScript: true },
          "node_modules/gitdep": { version: "1.0.0", resolved: "git+ssh://git@github.com/x/y.git" },
          "node_modules/linked": { resolved: "../linked", link: true },
          "node_modules/internal": { version: "1.0.0", resolved: "https://npm.corp.example/internal/-/internal-1.0.0.tgz" },
          "packages/ws": { version: "1.0.0" },
        },
      },
      null,
      2,
    );
    const { refs } = parsePackageLock(lock, "package-lock.json");
    const by = Object.fromEntries(refs.map((r) => [r.name, r]));
    expect(Object.keys(by).sort()).toEqual(["@s/c", "a", "b", "esbuild", "internal"]);
    expect(by.a).toMatchObject({ version: "1.0.0", direct: true });
    expect(by.b).toMatchObject({ version: "2.0.0", direct: false });
    expect(by["@s/c"]?.direct).toBe(false);
    expect(by.esbuild).toMatchObject({ direct: true, installScript: true });
    expect(by.internal?.private).toBe(true);
    expect(lock.split("\n")[(by.b?.line ?? 0) - 1]).toContain("node_modules/a/node_modules/b");
  });

  it("requirements: comments, -r, extras, markers, index urls, -e and URLs", () => {
    const text = [
      "# a comment",
      "-r other.txt",
      "-e git+https://github.com/x/y.git#egg=y",
      "https://example.com/pkg.whl",
      "requests[security]==2.31.0  # pinned",
      'numpy>=1.2; python_version<"3.9"',
      "Flask_Login >= 0.6, < 1",
      "django==4.2.* ",
      "pillow==10.0.0 \\",
      "    --hash=sha256:abc",
      "mylib @ https://example.com/mylib.zip",
    ].join("\n");
    const { refs, privateIndex } = parseRequirements(text, "requirements.txt");
    expect(privateIndex).toBe(false);
    expect(refs.map((r) => [r.name, r.version, r.line])).toEqual([
      ["requests", "2.31.0", 5],
      ["numpy", undefined, 6],
      ["flask-login", undefined, 7],
      ["django", undefined, 8],
      ["pillow", "10.0.0", 9],
    ]);
  });

  it("requirements: a private --index-url marks everything private, the public one does not", () => {
    const priv = parseRequirements("--index-url https://pypi.corp.example/simple\nacme-lib==1.0\n", "requirements.txt");
    expect(priv.privateIndex).toBe(true);
    expect(priv.refs[0]?.private).toBe(true);
    expect(parseRequirements("--extra-index-url https://pypi.org/simple\nrequests\n", "r.txt").privateIndex).toBe(false);
  });

  it("pyproject: multi-line dependencies array under [project] only", () => {
    const text = [
      "[build-system]",
      'requires = ["setuptools"]',
      "",
      "[project]",
      'name = "x"',
      "dependencies = [",
      '  "requests>=2.0",  # http',
      "  'Django[argon2]==4.2.1',",
      '  "numpy; python_version >= \\"3.9\\"",',
      "]",
      "[project.optional-dependencies]",
      'dev = ["pytest"]',
      "[tool.other]",
      'dependencies = ["not-this"]',
    ].join("\n");
    expect(parsePyproject(text, "pyproject.toml").map((r) => [r.name, r.version, r.line])).toEqual([
      ["requests", undefined, 7],
      ["django", "4.2.1", 8],
      ["numpy", undefined, 9],
    ]);
    expect(parsePyproject('[project]\ndependencies = ["a", "b[x]>=1"]\n', "p").map((r) => r.name)).toEqual(["a", "b"]);
  });

  it(".npmrc scoped registries and custom default registry", () => {
    const rc = parseNpmrc("# c\n@acme:registry=https://npm.corp.example/\nregistry=https://registry.npmjs.org/\n");
    expect([...rc.scopes]).toEqual(["@acme"]);
    expect(rc.customRegistry).toBe(false);
    expect(parseNpmrc("registry=https://npm.corp.example/").customRegistry).toBe(true);
  });
});

describe("typosquat matching", () => {
  const data = loadTyposquatData();
  it("loads the committed popular lists", () => {
    expect(data.npm.size).toBeGreaterThan(4000);
    expect(data.PyPI.size).toBeGreaterThan(4000);
  });
  it("matches the classic squats", () => {
    expect(data.npm.match("crossenv")).toMatchObject({ target: "cross-env", kind: "separator" });
    expect(data.PyPI.match("reqeusts")).toMatchObject({ target: "requests" });
    expect(data.PyPI.match("python3-dateutil")).toMatchObject({ target: "python-dateutil" });
    expect(data.PyPI.match("jeIlyfish")).toMatchObject({ target: "jellyfish" });
    expect(data.npm.match("types-node")).toMatchObject({ target: "@types/node" });
  });
  it("never matches popular packages themselves", () => {
    for (const n of ["express", "lodash", "cross-env", "react", "@types/node"]) expect(data.npm.match(n)).toBeUndefined();
    for (const n of ["requests", "Flask", "python_dateutil", "numpy"]) expect(data.PyPI.match(n)).toBeUndefined();
  });
  it("ignores short names at distance 1", () => {
    const idx = new PopularIndex(["ms", "chalk", "debug"], "npm");
    expect(idx.match("mz")).toBeUndefined();
    expect(idx.match("mx")).toBeUndefined();
    expect(idx.match("debu")).toBeUndefined();
  });
  it("allows distance 2 only for long names", () => {
    const idx = new PopularIndex(["express-session", "express"], "npm");
    expect(idx.match("express-sessoin")).toBeDefined(); // transposition
    expect(idx.match("expresss-sesion")).toBeDefined(); // 2 edits, >= 10 chars
    expect(idx.match("exprzzs")).toBeUndefined();
  });
  it("does not treat real siblings as typos", () => {
    const idx = new PopularIndex(["lodash.get", "listr2", "prompts", "@types/ws", "uuid"], "npm");
    expect(idx.match("lodash.set")).toBeUndefined();
    expect(idx.match("listr")).toBeUndefined();
    expect(idx.match("prompt")).toBeUndefined();
    expect(idx.match("@types/jws")).toBeUndefined();
    const py = new PopularIndex(["pyqt5-sip", "rfc3339-validator", "python-dateutil"], "PyPI");
    expect(py.match("pyqt6-sip")).toBeUndefined(); // version swap
    expect(py.match("rfc3986-validator")).toBeUndefined();
    expect(py.match("python-dateutil2")).toBeUndefined(); // trailing digit
    expect(py.match("python3-dateutil")).toBeDefined(); // digit inserted mid-name
  });
  it("respects data/typosquat-allow.json", () => {
    expect(data.allow.npm.has("babel-traverse")).toBe(true);
  });
  it("Damerau-Levenshtein counts transpositions as one edit", () => {
    expect(damerauLevenshtein("ab", "ba")).toBe(1);
    expect(damerauLevenshtein("kitten", "sitting")).toBe(3);
    expect(damerauLevenshtein("abcdef", "uvwxyz", 2)).toBe(3);
  });
});

describe("registry (fake fetch)", () => {
  const url = (n: string) => `https://registry.npmjs.org/${n}`;
  const retry = { sleep: async () => {}, now: () => NOW };

  it("404 → status 404", async () => {
    const { fetch } = fakeFetch({});
    const res = await new Registry({ fetch, ...retry }).lookup("npm", "nope-pkg");
    expect(res.record?.status).toBe(404);
  });

  it("retries 429 then succeeds", async () => {
    let n = 0;
    const { fetch, calls } = fakeFetch({ [url("a")]: () => (++n === 1 ? json({}, 429) : json(npmDoc(daysAgo(900)))) });
    const res = await new Registry({ fetch, ...retry }).lookup("npm", "a");
    expect(res.record?.status).toBe(200);
    expect(calls).toHaveLength(2);
  });

  it("gives up after 2 retries on 5xx", async () => {
    const { fetch, calls } = fakeFetch({ [url("a")]: () => json({}, 503) });
    const res = await new Registry({ fetch, ...retry }).lookup("npm", "a");
    expect(res.error).toBe("HTTP 503");
    expect(calls).toHaveLength(3);
  });

  it("a cache hit makes no request; 404s expire after 1h, others after 24h", async () => {
    const cacheDir = await mkdtemp(join(tmpdir(), "vigil-pkgrisk-cache-"));
    dirs.push(cacheDir);
    let t = NOW;
    const { fetch, calls } = fakeFetch({ [url("a")]: () => json(npmDoc(daysAgo(900))) });
    const reg = new Registry({ fetch, cacheDir, sleep: async () => {}, now: () => t });
    await reg.lookup("npm", "a");
    await reg.lookup("npm", "a");
    expect(calls).toHaveLength(1);
    await reg.lookup("npm", "ghost");
    t += 30 * 60_000;
    await reg.lookup("npm", "ghost");
    expect(calls).toHaveLength(2); // ghost: 1 request, 2nd within the hour was cached
    t += 31 * 60_000;
    await reg.lookup("npm", "ghost");
    expect(calls).toHaveLength(3);
    await reg.lookup("npm", "a");
    expect(calls).toHaveLength(3); // still within 24h
    t += 24 * 3_600_000;
    await reg.lookup("npm", "a");
    expect(calls).toHaveLength(4);
  });

  it("keeps the earliest first-publish date across refreshes", async () => {
    const cacheDir = await mkdtemp(join(tmpdir(), "vigil-pkgrisk-cache-"));
    dirs.push(cacheDir);
    let t = NOW;
    let created = daysAgo(900);
    const { fetch } = fakeFetch({ [url("a")]: () => json(npmDoc(created)) });
    const reg = new Registry({ fetch, cacheDir, sleep: async () => {}, now: () => t });
    await reg.lookup("npm", "a");
    t += 25 * 3_600_000;
    created = daysAgo(1);
    expect((await reg.lookup("npm", "a")).record?.created).toBe(daysAgo(900));
  });

  it("rejects malformed names without a request", async () => {
    const { fetch, calls } = fakeFetch({});
    const reg = new Registry({ fetch });
    expect((await reg.lookup("npm", "../../etc/passwd")).error).toBeDefined();
    expect((await reg.lookup("PyPI", "a/b")).error).toBeDefined();
    expect(calls).toHaveLength(0);
  });
});

describe("runPkgrisk", () => {
  const opts = (fetch: FetchLike) => ({ fetch, now: () => NOW, sleep: async () => {}, cacheDir: undefined as string | undefined });
  const NPM = (n: string) => `https://registry.npmjs.org/${n.replace("/", "%2F")}`;
  const PYPI = (n: string) => `https://pypi.org/pypi/${n}/json`;
  const pj = (deps: Record<string, string>) => JSON.stringify({ name: "app", dependencies: deps }, null, 2);

  it("404 on a direct dependency → critical pkg-nonexistent at the declaring line", async () => {
    const dir = await project({ "package.json": pj({ express: "^4", "react-hooks-ai-helper": "^1" }) });
    const { fetch } = fakeFetch({ [NPM("express")]: () => json(npmDoc(daysAgo(3000))) });
    const out = await runPkgrisk(dir, DEFAULT_IGNORES, opts(fetch));
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      engine: "pkgrisk",
      category: "dependency",
      ruleId: "pkg-nonexistent",
      severity: "critical",
      confidence: "high",
      location: { path: "package.json", startLine: 5 },
      dependency: { name: "react-hooks-ai-helper", ecosystem: "npm", advisories: [], fixedVersions: [] },
    });
  });

  it("new package (5 days) and new version (10 h) from lockfile versions", async () => {
    const dir = await project({
      "package.json": pj({ "fresh-lib": "^1", "old-lib": "^2" }),
      "package-lock.json": JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { "fresh-lib": "^1", "old-lib": "^2" } },
          "node_modules/fresh-lib": { version: "1.0.0" },
          "node_modules/old-lib": { version: "2.1.0" },
        },
      }),
    });
    const { fetch } = fakeFetch({
      [NPM("fresh-lib")]: () => json(npmDoc(daysAgo(5), { "1.0.0": daysAgo(5) })),
      [NPM("old-lib")]: () => json(npmDoc(daysAgo(2000), { "2.0.0": daysAgo(100), "2.1.0": hoursAgo(10) })),
    });
    const out = await runPkgrisk(dir, DEFAULT_IGNORES, opts(fetch));
    const rules = out.findings.map((f) => `${f.ruleId}:${f.dependency?.name}`).sort();
    expect(rules).toEqual(["pkg-new-package:fresh-lib", "pkg-new-version:old-lib"]);
    const nv = out.findings.find((f) => f.ruleId === "pkg-new-version");
    expect(nv?.severity).toBe("medium");
    expect(nv?.dependency?.version).toBe("2.1.0");
  });

  it("fingerprints ignore the version, except for pkg-new-version", async () => {
    const mk = async (version: string) => {
      const dir = await project({
        "package.json": pj({ "fresh-lib": "^1" }),
        "package-lock.json": JSON.stringify({
          lockfileVersion: 3,
          packages: { "": { dependencies: { "fresh-lib": "^1" } }, "node_modules/fresh-lib": { version } },
        }),
      });
      const { fetch } = fakeFetch({
        [NPM("fresh-lib")]: () => json(npmDoc(daysAgo(5), { "1.0.0": daysAgo(5), "1.0.1": hoursAgo(5) })),
      });
      return (await runPkgrisk(dir, DEFAULT_IGNORES, opts(fetch))).findings;
    };
    const a = await mk("1.0.0");
    const b = await mk("1.0.1");
    expect(a.map((f) => f.ruleId)).toEqual(["pkg-new-package"]);
    expect(b.map((f) => f.ruleId).sort()).toEqual(["pkg-new-package", "pkg-new-version"]);
    expect(b.find((f) => f.ruleId === "pkg-new-package")?.id).toBe(a[0]?.id);
  });

  it("typosquat with an install script reports both; a lone popular install script is only counted", async () => {
    const dir = await project({
      "package.json": pj({ crossenv: "^7", esbuild: "^0.2" }),
      "package-lock.json": JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { crossenv: "^7", esbuild: "^0.2" } },
          "node_modules/crossenv": { version: "7.0.0", hasInstallScript: true },
          "node_modules/esbuild": { version: "0.2.0", hasInstallScript: true },
        },
      }),
    });
    const out = await runPkgrisk(dir, DEFAULT_IGNORES, { offline: true });
    expect(out.findings.map((f) => `${f.ruleId}:${f.dependency?.name}`).sort()).toEqual([
      "pkg-install-script:crossenv",
      "pkg-typosquat:crossenv",
    ]);
    expect(out.warnings).toContain("pkgrisk: 1 dependencies run install scripts (not reported individually)");
  });

  it("PyPI: pinned new version, sdist-only direct dep outside the popular list, normalized names", async () => {
    const dir = await project({ "requirements.txt": "Some_Rare.Lib==1.0.0\nrequests==2.31.0\nreqeusts==1.0\n" });
    const rel = (ver: string, type: string, when: string) => ({ [ver]: [{ packagetype: type, upload_time_iso_8601: when }] });
    const { fetch, calls } = fakeFetch({
      [PYPI("some-rare-lib")]: () => json({ info: { version: "1.0.0" }, releases: rel("1.0.0", "sdist", hoursAgo(5)) }),
      [PYPI("requests")]: () => json({ info: { version: "2.32.0" }, releases: { ...rel("2.31.0", "bdist_wheel", daysAgo(900)), ...rel("2.32.0", "bdist_wheel", hoursAgo(2)) } }),
    });
    const out = await runPkgrisk(dir, DEFAULT_IGNORES, opts(fetch));
    const got = out.findings.map((f) => `${f.ruleId}:${f.dependency?.name}`).sort();
    // some-rare-lib's only release is 5 h old, so it is also a brand-new package.
    expect(got).toEqual([
      "pkg-new-package:some-rare-lib",
      "pkg-new-version:some-rare-lib",
      "pkg-nonexistent:reqeusts",
      "pkg-sdist-only:some-rare-lib",
      "pkg-typosquat:reqeusts",
    ]);
    expect(calls).toContain(PYPI("some-rare-lib"));
  });

  it("offline: no fetch calls, offline rules still run", async () => {
    const dir = await project({ "requirements.txt": "reqeusts==1.0\n" });
    const { fetch, calls } = fakeFetch({});
    const out = await runPkgrisk(dir, DEFAULT_IGNORES, { ...opts(fetch), offline: true });
    expect(calls).toHaveLength(0);
    expect(out.findings.map((f) => f.ruleId)).toEqual(["pkg-typosquat"]);
  });

  it("private npm scope from .npmrc is not looked up as a missing package; a public twin is a warning", async () => {
    const dir = await project({
      ".npmrc": "@acme:registry=https://npm.corp.example/\n",
      "package.json": pj({ "@acme/internal": "^1", "@acme/shadowed": "^1" }),
    });
    const { fetch } = fakeFetch({ [NPM("@acme/shadowed")]: () => json(npmDoc(daysAgo(10))) });
    const out = await runPkgrisk(dir, DEFAULT_IGNORES, opts(fetch));
    expect(out.findings).toEqual([]);
    expect(out.warnings.join("\n")).toMatch(/private package @acme\/shadowed .*dependency-confusion/);
    expect(out.warnings.join("\n")).not.toMatch(/@acme\/internal/);
  });

  it("registry unreachable is a warning, not a failure; offline rules still report", async () => {
    const dir = await project({ "package.json": pj({ crossenv: "^7", "some-lib": "^1" }) });
    const fetch: FetchLike = async () => {
      throw new TypeError("network down");
    };
    const out = await runPkgrisk(dir, DEFAULT_IGNORES, opts(fetch));
    expect(out.warnings).toContain("pkgrisk: registry unreachable, 2 packages not checked");
    expect(out.findings.map((f) => f.ruleId)).toEqual(["pkg-typosquat"]);
  });

  it("honours ignores and notes unsupported lockfiles", async () => {
    const dir = await project({
      "vendor/package.json": pj({ crossenv: "^7" }),
      "fixtures/requirements.txt": "reqeusts\n",
      "yarn.lock": "",
    });
    const out = await runPkgrisk(dir, [...DEFAULT_IGNORES, "fixtures"], { offline: true });
    expect(out.findings).toEqual([]);
    expect(out.warnings).toContain("pkgrisk: yarn.lock: not checked by pkgrisk");
  });

  it("sends only package names: URLs carry no paths or repo content", async () => {
    const dir = await project({ "package.json": pj({ "some-lib": "^1" }) });
    const { fetch, calls } = fakeFetch({});
    await runPkgrisk(dir, DEFAULT_IGNORES, opts(fetch));
    expect(calls).toEqual([NPM("some-lib")]);
  });
});

describe("scan() wiring", () => {
  it("--offline pkgrisk through scan() needs no binary and no network", async () => {
    const dir = await project({ "requirements.txt": "reqeusts==1.0\n" });
    const res = await scan(dir, { engines: ["pkgrisk"], offline: true });
    expect(res.engines).toMatchObject([{ engine: "pkgrisk", ok: true, findings: 1 }]);
    expect(res.findings[0]?.ruleId).toBe("pkg-typosquat");
  });
});

describe("osv MAL- advisories", () => {
  it("become critical pkg-known-malicious", () => {
    const findings = normalizeOsv("/repo", {
      results: [
        {
          source: { path: "/repo/package-lock.json", type: "lockfile" },
          packages: [
            {
              package: { name: "evil-pkg", version: "1.0.0", ecosystem: "npm" },
              vulnerabilities: [{ id: "MAL-2024-1234", summary: "Malicious code in evil-pkg" }],
              groups: [{ ids: ["MAL-2024-1234"] }],
            },
          ],
        },
      ],
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "pkg-known-malicious",
      severity: "critical",
      confidence: "high",
      category: "dependency",
      dependency: { name: "evil-pkg", advisories: ["MAL-2024-1234"] },
    });
  });
});
