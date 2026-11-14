import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { gateSeverity, type Finding, type Severity } from "../src/core/finding.js";
import { DEFAULT_IGNORES } from "../src/core/ignore.js";
import { findToken, jsImports, npmPackageOf, pyImports } from "../src/reachability/imports.js";
import { bunLockGraph, keysFor, npmLockGraph, pipCompileGraph, poetryDeclared, stripJsonc } from "../src/reachability/graph.js";
import { applyReachability, isReachabilityCandidate, scrubTooling } from "../src/reachability/index.js";
import { pythonAstImports } from "../src/reachability/pyast.js";
import { moduleCandidates } from "../src/reachability/pypi-modules.js";

const dirs: string[] = [];
async function project(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "vigil-reach-"));
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

function vuln(name: string, ecosystem: "npm" | "PyPI", path: string, severity: Severity = "high"): Finding {
  return {
    id: `id-${name}`,
    category: "dependency",
    engine: "osv-scanner",
    ruleId: "GHSA-xxxx",
    title: `${name} vulnerable`,
    message: "Vulnerable.",
    severity,
    location: { path, startLine: 1 },
    cwe: [],
    owasp: [],
    dependency: { name, version: "1.0.0", ecosystem, advisories: ["GHSA-xxxx"], fixedVersions: ["2.0.0"] },
  };
}

async function verdict(files: Record<string, string>, f: Finding): Promise<Finding> {
  const root = await project(files);
  await applyReachability(root, [f], DEFAULT_IGNORES);
  return f;
}

const pkg = (deps: Record<string, string>, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ name: "app", dependencies: deps, ...extra });

describe("import extraction", () => {
  it("npmPackageOf", () => {
    expect(npmPackageOf("lodash/merge")).toBe("lodash");
    expect(npmPackageOf("@a/b/c")).toBe("@a/b");
    expect(npmPackageOf("./x")).toBeUndefined();
    expect(npmPackageOf("node:fs")).toBeUndefined();
    expect(npmPackageOf("https://x")).toBeUndefined();
  });

  it("jsImports finds static forms and flags dynamic ones", () => {
    const r = jsImports(`import a from 'a';\nconst b = require("b/x");\nexport * from '@s/c';\nawait import('d');\n`);
    expect(r.imports.map((i) => i.name)).toEqual(["a", "b", "@s/c", "d"]);
    expect(r.dynamicLine).toBeUndefined();
    expect(jsImports(`const m = require(name);`).dynamicLine).toBe(1);
    expect(jsImports("x\nimport(`${p}/y`)").dynamicLine).toBe(2);
    expect(jsImports(`function require(x) {}\nobj.import(y)`).dynamicLine).toBeUndefined();
  });

  it("pyImports finds import, from-import and literal import_module", () => {
    const r = pyImports(`import os, yaml as y\nfrom requests.adapters import X\nimportlib.import_module("jinja2.x")\n`);
    expect(r.imports.map((i) => i.name)).toEqual(["requests", "os", "yaml", "jinja2"]);
    expect(r.dynamicLine).toBeUndefined();
    expect(pyImports(`x = 1\n__import__(name)`).dynamicLine).toBe(2);
  });

  it("findToken matches whole tokens, including after a path", () => {
    expect(findToken("run: /usr/bin/gunicorn app", "gunicorn")).toBe(1);
    expect(findToken("a\nnode_modules/.bin/vite build", "vite")).toBe(2);
    expect(findToken("vitest run", "vite")).toBeUndefined();
  });

  it("findToken skips file names and absolute paths that only look like packages", () => {
    expect(findToken("path: ~/.npm", "npm")).toBeUndefined();
    expect(findToken("FLASK_APP: autoapp.py", "py")).toBeUndefined();
    expect(findToken("RUN mkdir /tmp/extracted_files", "tmp")).toBeUndefined();
    expect(findToken("/tmp/x", "tmp")).toBeUndefined();
    expect(findToken("node node_modules/tmp/cli.js", "tmp")).toBe(1);
    expect(findToken("npm ci", "npm")).toBe(1);
  });

  it("scrubTooling drops comments and YAML step titles, keeping line numbers", () => {
    const yml = "steps:\n  - name: Prepare cypress artifacts\n    # Simple request\n    run: npx cypress run # not request\n";
    const out = scrubTooling(".github/workflows/e2e.yml", yml);
    expect(out.split("\n")).toHaveLength(yml.split("\n").length);
    expect(findToken(out, "cypress")).toBe(4);
    expect(findToken(out, "request")).toBeUndefined();
    expect(findToken(scrubTooling("Dockerfile", "# syntax = docker/dockerfile:1\nFROM node"), "dockerfile")).toBeUndefined();
    expect(findToken(scrubTooling("vite.config.ts", "// uses legacy\nplugins: [legacy()]"), "legacy")).toBe(2);
  });

  it("moduleCandidates maps distributions to import names", () => {
    expect(moduleCandidates("PyYAML")).toContain("yaml");
    expect(moduleCandidates("python-dateutil")).toContain("dateutil");
    expect(moduleCandidates("google-cloud-storage")).toContain("google");
    expect(moduleCandidates("Flask_Login")).toContain("flask_login");
  });
});

/** package-lock v3 from `deps` (name → its own dependencies). Top-level names are the project's. */
function lock(direct: string[], deps: Record<string, string[]> = {}, dev: string[] = []): string {
  const packages: Record<string, unknown> = {
    "": { name: "app", dependencies: Object.fromEntries(direct.map((d) => [d, "1"])), devDependencies: Object.fromEntries(dev.map((d) => [d, "1"])) },
  };
  const all = new Set([...direct, ...dev, ...Object.keys(deps), ...Object.values(deps).flat()]);
  for (const n of all) packages[`node_modules/${n}`] = { version: "1.0.0", dependencies: Object.fromEntries((deps[n] ?? []).map((d) => [d, "1"])) };
  return JSON.stringify({ lockfileVersion: 3, packages });
}

describe("applyReachability: npm", () => {
  it("reachable when imported, with evidence", async () => {
    const f = await verdict(
      { "package.json": pkg({ lodash: "1" }), "package-lock.json": lock(["lodash"]), "src/a.ts": "\nimport merge from 'lodash/merge';" },
      vuln("lodash", "npm", "package-lock.json"),
    );
    expect(f.reachability?.status).toBe("reachable");
    expect(f.reachability?.evidence).toEqual({ path: "src/a.ts", line: 2 });
    expect(f.severity).toBe("high");
  });

  it("reachable when its bin is used in an npm script", async () => {
    const lk = JSON.stringify({ packages: { "": { dependencies: { typescript: "1" } }, "node_modules/typescript": { version: "1.0.0", bin: { tsc: "bin/tsc" } } } });
    const f = await verdict(
      { "package.json": pkg({ typescript: "1" }, { scripts: { build: "tsc -p ." } }), "package-lock.json": lk },
      vuln("typescript", "npm", "package-lock.json"),
    );
    expect(f.reachability?.status).toBe("reachable");
  });

  it("prose, cache paths and quoted words don't make an undeclared package reachable", async () => {
    const files = {
      "package.json": pkg({ express: "1", legacy: "1" }),
      "package-lock.json": lock(["express", "legacy"], { legacy: ["request"], request: ["tough-cookie"] }),
      "index.js": "require('express');\nconst opts = { mode: \"request\" };",
      ".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - name: Simple request\n        with:\n          path: ~/.npm\n      # request goes here\n",
    };
    for (const name of ["request", "tough-cookie"]) {
      const f = await verdict(files, vuln(name, "npm", "package-lock.json"));
      expect(f.reachability?.status, f.reachability?.reason).toBe("unreachable");
    }
  });

  it("system npm, one-letter names and rc-file comments don't count for undeclared packages", async () => {
    const files = {
      "package.json": pkg({ express: "1", legacy: "1" }),
      "package-lock.json": lock(["express", "legacy"], { legacy: ["npm", "d", "i"] }),
      "index.js": "require('express');",
      ".github/workflows/ci.yml": "steps:\n  - run: npm ci && find . -type d\n",
      ".jshintrc": '{\n  "eqeqeq": true // i.e. ===\n}\n',
    };
    for (const name of ["npm", "d", "i"]) {
      const f = await verdict(files, vuln(name, "npm", "package-lock.json"));
      expect(f.reachability?.status, f.reachability?.reason).toBe("unreachable");
    }
    // Declared directly, the same mention counts.
    const own = await verdict({ ...files, "package.json": pkg({ express: "1", legacy: "1", npm: "1" }), "package-lock.json": lock(["express", "legacy", "npm"]) }, vuln("npm", "npm", "package-lock.json"));
    expect(own.reachability?.status).toBe("reachable");
  });

  it("package.json script names don't count, their commands do", async () => {
    const lockWith = lock(["express", "legacy"], { legacy: ["tsx"] });
    const base = { "package-lock.json": lockWith, "index.js": "require('express');" };
    const byName = await verdict({ ...base, "package.json": pkg({ express: "1", legacy: "1" }, { scripts: { "tsx:watch": "node x.js" } }) }, vuln("tsx", "npm", "package-lock.json"));
    expect(byName.reachability?.status).toBe("unreachable");
    const byCmd = await verdict({ ...base, "package.json": pkg({ express: "1", legacy: "1" }, { scripts: { dev: "tsx watch x.ts" } }) }, vuln("tsx", "npm", "package-lock.json"));
    expect(byCmd.reachability?.status).toBe("reachable");
  });

  it("reachable when named as a string (knex client)", async () => {
    const f = await verdict(
      { "package.json": pkg({ knex: "1", pg: "1" }), "package-lock.json": lock(["knex", "pg"]), "db.js": "require('knex')({ client: 'pg' })" },
      vuln("pg", "npm", "package-lock.json"),
    );
    expect(f.reachability?.status).toBe("reachable");
  });

  it("an unused direct dependency is unreachable; declaring it is not use", async () => {
    const f = await verdict(
      { "package.json": pkg({ lodash: "1", express: "1" }), "package-lock.json": lock(["lodash", "express"]), "index.js": "require('express')" },
      vuln("lodash", "npm", "package-lock.json", "high"),
    );
    expect(f.reachability?.status).toBe("unreachable");
    expect(f.reachability?.originalSeverity).toBe("high");
    expect(f.severity).toBe("medium");
    expect(f.message).toContain("Likely unreachable");
  });

  it("a direct dependency that a used package depends on is reachable (not unreachable)", async () => {
    const f = await verdict(
      { "package.json": pkg({ qs: "1", express: "1" }), "package-lock.json": lock(["qs", "express"], { express: ["body-parser"], "body-parser": ["qs"] }), "index.js": "require('express')" },
      vuln("qs", "npm", "package-lock.json"),
    );
    expect(f.reachability?.status).toBe("reachable");
    expect(f.reachability?.reason).toContain("express");
  });

  it("transitive: reachable through a used parent, unreachable when every parent is unused", async () => {
    const files = (code: string) => ({
      "package.json": pkg({ express: "1", request: "1" }),
      "package-lock.json": lock(["express", "request"], { express: ["qs"], request: ["tough-cookie"] }),
      "index.js": code,
    });
    const used = await verdict(files("require('express')"), vuln("qs", "npm", "package-lock.json"));
    expect(used.reachability?.status).toBe("reachable");
    expect(used.reachability?.evidence?.path).toBe("index.js");

    const unused = await verdict(files("require('express')"), vuln("tough-cookie", "npm", "package-lock.json"));
    expect(unused.reachability?.status).toBe("unreachable");
    expect(unused.reachability?.reason).toContain("request");
  });

  it("unknown when a used library loads it by name at runtime", async () => {
    const f = await verdict(
      { "package.json": pkg({ sequelize: "1", pg: "1" }), "package-lock.json": lock(["sequelize", "pg"]), "db.js": "const { Sequelize } = require('sequelize');" },
      vuln("pg", "npm", "package-lock.json"),
    );
    expect(f.reachability?.status).toBe("unknown");
    expect(f.reachability?.reason).toContain("sequelize");
  });

  it("unknown for dev, dynamic, no lockfile graph, and unsupported lockfiles", async () => {
    const dev = await verdict(
      { "package.json": JSON.stringify({ devDependencies: { mocha: "1" } }), "package-lock.json": lock([], { mocha: ["debug"] }, ["mocha"]) },
      vuln("debug", "npm", "package-lock.json"),
    );
    expect(dev.reachability?.status).toBe("unknown");

    const dyn = await verdict(
      { "package.json": pkg({ lodash: "1" }), "package-lock.json": lock(["lodash"]), "a.js": "require(plugin)" },
      vuln("lodash", "npm", "package-lock.json"),
    );
    expect(dyn.reachability?.status).toBe("unknown");
    expect(dyn.severity).toBe("high");

    const nolock = await verdict({ "package.json": pkg({ lodash: "1" }) }, vuln("lodash", "npm", "package-lock.json"));
    expect(nolock.reachability?.status).toBe("unknown");

    const pnpm = await verdict({ "package.json": pkg({ lodash: "1" }), "pnpm-lock.yaml": "lockfileVersion: '9.0'\n" }, vuln("lodash", "npm", "pnpm-lock.yaml"));
    expect(pnpm.reachability?.status).toBe("unknown");
    expect(pnpm.reachability?.reason).toContain("pnpm");
  });

  it("bun.lock graph: workspaces, nested copies, trailing commas", async () => {
    const bun = `{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "root", },
    "web": {
      "name": "web",
      "dependencies": { "express": "^4", "@a/b": "1", },
      "devDependencies": { "jest": "^29", },
    },
  },
  "packages": {
    "express": ["express@4.0.0", "", { "dependencies": { "qs": "^6", "debug": "2" } }, "sha512-x"],
    "qs": ["qs@6.0.0", "", {}, "sha512-x"],
    "debug": ["debug@4.0.0", "", {}, "sha512-x"],
    "express/debug": ["debug@2.0.0", "", { "dependencies": { "ms": "2" } }, "sha512-x"],
    "ms": ["ms@2.0.0", "", {}, "sha512-x"],
    "@a/b": ["@a/b@1.0.0", "", { "dependencies": { "qs": "5", "only-b": "1" } }, "sha512-x"],
    "@a/b/qs": ["qs@5.0.0", "", {}, "sha512-x"],
    "jest": ["jest@29.0.0", "", { "dependencies": { "tough": "4" }, "bin": { "jest": "bin/jest.js" } }, "sha512-x"],
    "tough": ["tough@4.0.0", "", {}, "sha512-x"],
    "only-b": ["only-b@1.0.0", "", {}, "sha512-x"],
    "lonely": ["lonely@1.0.0", "", {}, "sha512-x"],
    "web": ["web@workspace:web"],
  },
}`;
    expect(stripJsonc('{"a": "x,}", // c\n "b": [1,],}')).toBe('{"a": "x,}", \n "b": [1]}');
    const g = bunLockGraph(bun)!;
    expect([...g.roots].sort()).toEqual(["@a/b", "express"]);
    expect([...g.devRoots]).toEqual(["jest"]);
    expect(g.nodes.has("web")).toBe(false);
    expect([...g.parents.get("express/debug")!]).toEqual(["express"]);
    expect([...g.parents.get("ms")!]).toEqual(["express/debug"]);
    expect([...g.parents.get("@a/b/qs")!]).toEqual(["@a/b"]);
    expect(g.parents.has("debug")).toBe(false); // express uses its nested copy
    expect(keysFor(g, "qs", "5.0.0")).toEqual(["@a/b/qs"]);

    const files = { "package.json": pkg({}, { workspaces: ["web"] }), "bun.lock": bun, "web/index.js": "import express from 'express'" };
    expect((await verdict(files, vuln("ms", "npm", "bun.lock"))).reachability?.status).toBe("reachable");
    const onlyB = await verdict(files, vuln("only-b", "npm", "bun.lock"));
    expect(onlyB.reachability?.status, onlyB.reachability?.reason).toBe("unreachable");
    expect((await verdict(files, vuln("lonely", "npm", "bun.lock"))).reachability?.status).toBe("unknown"); // orphan
    expect((await verdict(files, vuln("tough", "npm", "bun.lock"))).reachability?.status).toBe("unknown"); // dev-only
    expect((await verdict({ ...files, "bun.lock": "{ not json" }, vuln("lonely", "npm", "bun.lock"))).reachability?.status).toBe("unknown");
  });

  it("yarn.lock (classic) graph", async () => {
    const yarn = [
      "# yarn lockfile v1",
      "",
      "express@^4.0.0:",
      '  version "4.17.1"',
      "  dependencies:",
      '    qs "6.7.0"',
      "",
      'request@^2.0.0:',
      '  version "2.88.0"',
      "  dependencies:",
      '    tough-cookie "~2.4.3"',
      "",
      "qs@6.7.0:",
      '  version "6.7.0"',
      "",
      "tough-cookie@~2.4.3:",
      '  version "2.4.3"',
      "",
    ].join("\n");
    const files = { "package.json": pkg({ express: "^4.0.0", request: "^2.0.0" }), "yarn.lock": yarn, "index.js": "import express from 'express'" };
    expect((await verdict(files, vuln("qs", "npm", "yarn.lock"))).reachability?.status).toBe("reachable");
    expect((await verdict(files, vuln("tough-cookie", "npm", "yarn.lock"))).reachability?.status).toBe("unreachable");
  });

  it("analyzes the lockfile's own directory in a monorepo", async () => {
    const files = {
      "packages/web/package.json": pkg({ lodash: "1" }),
      "packages/web/package-lock.json": lock(["lodash"]),
      "packages/api/index.js": "require('lodash')",
    };
    const f = await verdict(files, vuln("lodash", "npm", "packages/web/package-lock.json"));
    expect(f.reachability?.status).toBe("unreachable");
  });

  it("never lowers below info", async () => {
    const f = await verdict(
      { "package.json": pkg({ lodash: "1" }), "package-lock.json": lock(["lodash"]) },
      vuln("lodash", "npm", "package-lock.json", "info"),
    );
    expect(f.reachability?.status).toBe("unreachable");
    expect(f.severity).toBe("info");
    expect(f.reachability?.originalSeverity).toBeUndefined();
  });
});

const compiled = (lines: string[]) => lines.join("\n") + "\n";

describe("applyReachability: PyPI", () => {
  const reqs = compiled([
    "flask==2.0.1",
    "    # via -r requirements.in",
    "jinja2==3.0.1",
    "    # via flask",
    "markupsafe==2.0.1",
    "    # via",
    "    #   jinja2",
    "    #   werkzeug",
    "requests==2.20.0",
    "    # via -r requirements.in",
    "urllib3==1.24.1",
    "    # via requests",
    "werkzeug==2.0.1",
    "    # via flask",
  ]);

  it("pip-compile graph: transitive through a used package is reachable, through an unused one unreachable", async () => {
    const files = { "requirements.txt": reqs, "app.py": "from flask import Flask\n" };
    const md = await verdict(files, vuln("markupsafe", "PyPI", "requirements.txt"));
    expect(md.reachability?.status).toBe("reachable");
    expect(md.reachability?.reason).toContain("flask");
    const u3 = await verdict(files, vuln("urllib3", "PyPI", "requirements.txt"));
    expect(u3.reachability?.status).toBe("unreachable");
    expect(u3.reachability?.reason).toContain("requests");
  });

  it("a flat requirements.txt (no via comments) gives unknown, not unreachable", async () => {
    const f = await verdict(
      { "requirements.txt": "flask==2.0.1\nmarkupsafe==2.0.1\n", "app.py": "import flask\n" },
      vuln("markupsafe", "PyPI", "requirements.txt"),
    );
    expect(f.reachability?.status).toBe("unknown");
  });

  it("reachable through a distribution → module mapping", async () => {
    const f = await verdict({ "requirements.txt": "PyYAML==5.1\n", "app/main.py": "import yaml\n" }, vuln("PyYAML", "PyPI", "requirements.txt"));
    expect(f.reachability?.status).toBe("reachable");
  });

  it("reachable when named as a string (Django INSTALLED_APPS) or run from a Dockerfile", async () => {
    const cors = await verdict(
      { "requirements.txt": "django-cors-headers==1\n", "settings.py": "INSTALLED_APPS = ['corsheaders']\n" },
      vuln("django-cors-headers", "PyPI", "requirements.txt"),
    );
    expect(cors.reachability?.status).toBe("reachable");
    const gun = await verdict({ "requirements.txt": "gunicorn==19\n", Dockerfile: 'CMD ["gunicorn", "app:app"]\n' }, vuln("gunicorn", "PyPI", "requirements.txt"));
    expect(gun.reachability?.status).toBe("reachable");
  });

  it("a quoted word or a .py file name doesn't make an undeclared package reachable", async () => {
    const files = {
      "requirements.txt": compiled(["flask==2.0.1", "    # via -r requirements.in", "legacy==1.0", "    # via -r requirements.in", "py==1.0", "    # via legacy"]),
      "app.py": "import flask\nKIND = 'py'\n",
      ".circleci/config.yml": "env:\n  FLASK_APP: autoapp.py\n",
    };
    const f = await verdict(files, vuln("py", "PyPI", "requirements.txt"));
    expect(f.reachability?.status, f.reachability?.reason).toBe("unreachable");
  });

  it("guessed module names count in config only after -m (pytest is not a `test:` key)", async () => {
    const reqs2 = compiled(["legacy==1.0", "    # via -r requirements.in", "python-dotenv==1.0", "    # via legacy", "pytest==7.0", "    # via legacy"]);
    const ci = "jobs:\n  test:\n    run: python -m dotenv run app\n";
    const dot = await verdict({ "requirements.txt": reqs2, "ci.yml": ci }, vuln("python-dotenv", "PyPI", "requirements.txt"));
    expect(dot.reachability?.status).toBe("reachable");
    const pt = await verdict({ "requirements.txt": reqs2, "ci.yml": ci }, vuln("pytest", "PyPI", "requirements.txt"));
    expect(pt.reachability?.status, pt.reachability?.reason).toBe("unreachable");
  });

  it("an import inside a docstring doesn't count (Python ast)", async () => {
    const reqs2 = compiled(["jinja2==2.0", "    # via -r requirements.in"]);
    const f = await verdict(
      { "requirements.txt": reqs2, "app.py": '"""\nimport jinja2\n"""\nimport os\n' },
      vuln("jinja2", "PyPI", "requirements.txt"),
    );
    expect(f.reachability?.status).toBe("unreachable");
  });

  it("uv.lock graph, with the dependency line in pyproject not counting as use", async () => {
    const pyproject = `[project]\nname = "app"\ndependencies = [\n  "fastapi==0.1",\n  "markdown==2.0",\n]\n`;
    const uv = [
      "version = 1",
      "",
      "[[package]]",
      'name = "app"',
      'version = "0.1.0"',
      'source = { virtual = "." }',
      "dependencies = [",
      '    { name = "fastapi" },',
      '    { name = "markdown" },',
      "]",
      "",
      "[package.dev-dependencies]",
      'dev = [{ name = "pytest" }]',
      "",
      "[[package]]",
      'name = "fastapi"',
      'version = "0.1"',
      'dependencies = [{ name = "starlette" }]',
      "",
      "[[package]]",
      'name = "starlette"',
      'version = "0.1"',
      "",
      "[[package]]",
      'name = "markdown"',
      'version = "2.0"',
      'dependencies = [{ name = "importlib-metadata" }]',
      "",
      "[[package]]",
      'name = "importlib-metadata"',
      'version = "1.0"',
      "",
      "[[package]]",
      'name = "pytest"',
      'version = "1.0"',
      "",
    ].join("\n");
    const files = { "pyproject.toml": pyproject, "uv.lock": uv, "main.py": "from fastapi import FastAPI\n" };
    expect((await verdict(files, vuln("starlette", "PyPI", "uv.lock"))).reachability?.status).toBe("reachable");
    expect((await verdict(files, vuln("markdown", "PyPI", "uv.lock"))).reachability?.status).toBe("unreachable");
    expect((await verdict(files, vuln("importlib-metadata", "PyPI", "uv.lock"))).reachability?.status).toBe("unreachable");
    expect((await verdict(files, vuln("pytest", "PyPI", "uv.lock"))).reachability?.status).toBe("unknown");
    // FastAPI renders templates through jinja2 without the project importing it.
    const withJinja = { ...files, "uv.lock": uv.replace(/"markdown"/g, '"jinja2"'), "pyproject.toml": pyproject.replace("markdown", "jinja2") };
    expect((await verdict(withJinja, vuln("jinja2", "PyPI", "uv.lock"))).reachability?.status).toBe("unknown");
  });

  it("poetry.lock graph with roots from [tool.poetry.*]", async () => {
    const pyproject = `[tool.poetry.dependencies]\npython = "^3.10"\nrequests = "^2"\nflask = "^2"\n\n[tool.poetry.group.dev.dependencies]\npytest = "^7"\n`;
    const poetry = [
      "[[package]]",
      'name = "requests"',
      'version = "2.20.0"',
      "",
      "[package.dependencies]",
      'urllib3 = ">=1.21"',
      "",
      "[[package]]",
      'name = "urllib3"',
      'version = "1.24.1"',
      "",
      "[[package]]",
      'name = "flask"',
      'version = "2.0.1"',
      "",
      "[[package]]",
      'name = "pytest"',
      'version = "7.0"',
      "",
      "[metadata]",
      'lock-version = "2.0"',
    ].join("\n");
    const files = { "pyproject.toml": pyproject, "poetry.lock": poetry, "app.py": "import flask\n" };
    const u3 = await verdict(files, vuln("urllib3", "PyPI", "poetry.lock", "critical"));
    expect(u3.reachability?.status).toBe("unreachable");
    expect(u3.severity).toBe("high");
    expect((await verdict(files, vuln("pytest", "PyPI", "poetry.lock"))).reachability?.status).toBe("unknown");
    const used = await verdict({ ...files, "app.py": "import requests\n" }, vuln("urllib3", "PyPI", "poetry.lock"));
    expect(used.reachability?.status).toBe("reachable");
  });

  it("unknown when SQLAlchemy can load the driver by URL", async () => {
    const r = compiled(["sqlalchemy==1.0", "    # via -r requirements.in", "psycopg2==2.0", "    # via -r requirements.in"]);
    const f = await verdict({ "requirements.txt": r, "db.py": "import sqlalchemy\n" }, vuln("psycopg2", "PyPI", "requirements.txt"));
    expect(f.reachability?.status).toBe("unknown");
  });
});

describe("graph parsers", () => {
  it("npm lock v1 uses package.json for the roots", () => {
    const v1 = JSON.stringify({ lockfileVersion: 1, dependencies: { express: { version: "4.0.0", requires: { qs: "1" } }, qs: { version: "1.0.0" } } });
    const g = npmLockGraph(v1, { prod: new Map([["express", "4"]]), dev: new Map() })!;
    expect([...g.roots]).toEqual(["node_modules/express"]);
    expect([...(g.parents.get("node_modules/qs") ?? [])]).toEqual(["node_modules/express"]);
  });

  it("npm lock resolves nested copies before hoisted ones", () => {
    const lk = JSON.stringify({
      packages: {
        "": { dependencies: { a: "1", b: "1" } },
        "node_modules/a": { version: "1", dependencies: { c: "2" } },
        "node_modules/a/node_modules/c": { version: "2" },
        "node_modules/b": { version: "1", dependencies: { c: "1" } },
        "node_modules/c": { version: "1" },
      },
    });
    const g = npmLockGraph(lk)!;
    expect([...(g.parents.get("node_modules/a/node_modules/c") ?? [])]).toEqual(["node_modules/a"]);
    expect([...(g.parents.get("node_modules/c") ?? [])]).toEqual(["node_modules/b"]);
    expect(keysFor(g, "c", "2")).toEqual(["node_modules/a/node_modules/c"]);
  });

  it("pip-compile: files without via comments give no graph", () => {
    expect(pipCompileGraph([{ text: "flask==1\n", dev: false }])).toBeUndefined();
  });

  it("poetryDeclared reads Poetry tables, PEP 621 arrays and groups, not other arrays", () => {
    const d = poetryDeclared(
      `[project]\nclassifiers = ["Framework :: Flask"]\ndependencies = ["uvicorn[standard]>=0.2",\n  "httpx"]\n[project.optional-dependencies]\nsql = ["sqlalchemy"]\n[dependency-groups]\ndev = ["pytest"]\n[tool.poetry.dependencies]\npython = "^3"\nDjango = "^4"\n`,
    );
    expect([...d.prod].sort()).toEqual(["django", "httpx", "sqlalchemy", "uvicorn"]);
    expect([...d.dev]).toEqual(["pytest"]);
  });
});

describe("pythonAstImports", () => {
  it("parses real imports, skips docstrings, and leaves unparseable files to the regex", async () => {
    const root = await project({ "a.py": '"""import fake"""\nimport os.path\nfrom x.y import z\nimportlib.import_module(name)\n', "py2.py": "print 'hi'\n" });
    const m = await pythonAstImports([join(root, "a.py"), join(root, "py2.py")]);
    expect(m.get(join(root, "a.py"))).toEqual({ imports: [{ name: "os", line: 2 }, { name: "x", line: 3 }], dynamicLine: 4 });
    expect(m.has(join(root, "py2.py"))).toBe(false);
  });

  it("returns an empty map when python is missing", async () => {
    expect((await pythonAstImports(["/x.py"], "/nonexistent/python3")).size).toBe(0);
  });
});

describe("CI gate", () => {
  it("unreachable findings still block at their original severity unless trusted", async () => {
    const f = await verdict({ "package.json": pkg({ lodash: "1" }), "package-lock.json": lock(["lodash"]) }, vuln("lodash", "npm", "package-lock.json", "high"));
    expect(f.severity).toBe("medium");
    expect(gateSeverity(f)).toBe("high");
    expect(gateSeverity(f, true)).toBe("medium");
  });
});

describe("candidates", () => {
  it("skips malicious packages, other engines and other ecosystems", () => {
    expect(isReachabilityCandidate(vuln("x", "npm", "p"))).toBe(true);
    expect(isReachabilityCandidate({ ...vuln("x", "npm", "p"), ruleId: "pkg-known-malicious" })).toBe(false);
    expect(isReachabilityCandidate({ ...vuln("x", "npm", "p"), engine: "pkgrisk" })).toBe(false);
    const go = vuln("x", "npm", "p");
    go.dependency!.ecosystem = "Go";
    expect(isReachabilityCandidate(go)).toBe(false);
  });
});
