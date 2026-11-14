import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { PassThrough } from "node:stream";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "../src/core/finding.js";
import type { FetchLike } from "../src/engines/pkgrisk/registry.js";
import { PROTOCOL_VERSIONS, serve, ToolError, type Tool } from "../src/mcp/protocol.js";
import { createTools } from "../src/mcp/tools.js";
import type { ScanOptions, ScanResult } from "../src/scan.js";

const exec = promisify(execFile);
const IDENT = ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"];

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function tempDir(files: Record<string, string> = {}): Promise<string> {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "vigil-mcp-test-")));
  dirs.push(dir);
  for (const [name, body] of Object.entries(files)) {
    await mkdir(dirname(join(dir, name)), { recursive: true });
    await writeFile(join(dir, name), body);
  }
  return dir;
}

const git = (cwd: string, ...args: string[]) => exec("git", [...IDENT, ...args], { cwd });

/** Send lines to a server, collect every reply once input ends. */
async function rpc(tools: Tool[], lines: unknown[]): Promise<Array<Record<string, any>>> {
  const input = new PassThrough();
  const output = new PassThrough();
  let out = "";
  output.on("data", (c) => (out += String(c)));
  const done = serve({ name: "vigil", version: "0.0.0", instructions: "hi" }, tools, { input, output });
  for (const l of lines) input.write((typeof l === "string" ? l : JSON.stringify(l)) + "\n");
  input.end();
  await done;
  return out
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

const call = (id: number, name: string, args: Record<string, unknown> = {}) => ({
  jsonrpc: "2.0",
  id,
  method: "tools/call",
  params: { name, arguments: args },
});

function finding(path: string, line: number, severity: Finding["severity"], extra: Partial<Finding> = {}): Finding {
  return {
    id: `${path}:${line}:${severity}`,
    category: "code",
    engine: "opengrep",
    ruleId: "js-x",
    title: `t ${path}`,
    message: "what, why, fix",
    severity,
    location: { path, startLine: line, snippet: "SECRET_CODE()" },
    cwe: ["CWE-89: SQL Injection"],
    owasp: ["A03:2021 - Injection"],
    ...extra,
  };
}

describe("protocol", () => {
  const echo: Tool = {
    name: "echo",
    description: "d",
    inputSchema: { type: "object" },
    handler: async (args) => {
      if (args.bad) throw new ToolError("bad argument");
      if (args.boom) throw new Error("internal detail");
      return { got: args };
    },
  };

  it("negotiates the version, lists tools without handlers, and ignores notifications", async () => {
    const replies = await rpc(
      [echo],
      [
        { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {} } },
        { jsonrpc: "2.0", method: "notifications/initialized" },
        { jsonrpc: "2.0", id: 2, method: "initialize", params: { protocolVersion: "1999-01-01" } },
        { jsonrpc: "2.0", id: 3, method: "tools/list" },
        { jsonrpc: "2.0", id: "p", method: "ping" },
      ],
    );
    expect(replies).toHaveLength(4);
    const byId = new Map(replies.map((r) => [r.id, r]));
    expect(byId.get(1)!.result).toMatchObject({ protocolVersion: "2025-03-26", serverInfo: { name: "vigil" }, instructions: "hi", capabilities: { tools: {} } });
    expect(byId.get(2)!.result.protocolVersion).toBe(PROTOCOL_VERSIONS[0]);
    expect(byId.get(3)!.result.tools).toEqual([{ name: "echo", description: "d", inputSchema: { type: "object" } }]);
    expect(byId.get("p")!.result).toEqual({});
  });

  it("maps errors to JSON-RPC codes and tool failures to isError results", async () => {
    const replies = await rpc(
      [echo],
      [
        "{not json",
        [{ jsonrpc: "2.0", id: 9, method: "ping" }],
        { jsonrpc: "2.0", id: 1, method: "nope" },
        call(2, "missing"),
        call(3, "echo", { bad: true }),
        call(4, "echo", { boom: true }),
        call(5, "echo", { a: 1 }),
        { jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "echo", arguments: [1] } },
        { jsonrpc: "2.0", id: 7, result: {} }, // a response: ignored
      ],
    );
    const byId = new Map(replies.filter((r) => r.id !== null).map((r) => [r.id, r]));
    const nulls = replies.filter((r) => r.id === null).map((r) => r.error.code);
    expect(nulls.sort()).toEqual([-32600, -32700]);
    expect(byId.get(1)!.error.code).toBe(-32601);
    expect(byId.get(2)!.error.code).toBe(-32602);
    expect(byId.get(3)!.result).toEqual({ content: [{ type: "text", text: "bad argument" }], isError: true });
    expect(byId.get(4)!.result.isError).toBe(true);
    expect(JSON.parse(byId.get(5)!.result.content[0].text)).toEqual({ got: { a: 1 } });
    expect(byId.get(6)!.error.code).toBe(-32602);
    expect(byId.has(7)).toBe(false);
  });
});

describe("scan tool", () => {
  /** A fake scanner: one high finding per file it finds under the target, and records each call. */
  function fakeScan() {
    const calls: Array<{ target: string; opts: ScanOptions; files: string[] }> = [];
    const scan = async (target: string, opts: ScanOptions): Promise<ScanResult> => {
      const files = (await readdir(target, { recursive: true, withFileTypes: true }))
        .filter((e) => e.isFile())
        .map((e) => join(e.parentPath, e.name).slice(target.length + 1))
        .sort();
      calls.push({ target, opts, files });
      return {
        root: target,
        findings: files.map((f, i) => finding(f, i + 1, i % 2 ? "critical" : "low")),
        ignores: [],
        warnings: [`warning in ${target}/x`],
        engines: (opts.engines ?? []).map((engine) => ({ engine, ok: true, findings: 0, ms: 1 })),
      };
    };
    return { scan, calls };
  }

  async function repo(): Promise<string> {
    const dir = await tempDir({ "a.js": "a", "b.js": "b", "package.json": "{}", ".vigilignore": "gen/\n", ".gitignore": "out/\n" });
    await git(dir, "init", "-q");
    await git(dir, "add", "-A");
    await git(dir, "commit", "-qm", "init");
    return dir;
  }

  async function scanVia(dir: string, args: Record<string, unknown>, fake = fakeScan()) {
    const [reply] = await rpc(createTools(dir, { scan: fake.scan }), [call(1, "scan", args)]);
    const res = reply!.result;
    return { res, body: res.isError ? res.content[0].text : JSON.parse(res.content[0].text), calls: fake.calls };
  }

  it("default scope: only changed + untracked files, in a temp copy, code engines only", async () => {
    const dir = await repo();
    await writeFile(join(dir, "a.js"), "changed");
    await writeFile(join(dir, "new.py"), "x");
    await mkdir(join(dir, "gen"));
    await writeFile(join(dir, "gen", "g.js"), "x"); // .vigilignore'd
    await mkdir(join(dir, "out"));
    await writeFile(join(dir, "out", "o.js"), "x"); // .gitignore'd
    await writeFile(join(dir, "bin.dat"), Buffer.from([0, 1, 2]));

    const { body, calls } = await scanVia(dir, {});
    expect(calls).toHaveLength(1);
    expect(calls[0]!.target).not.toBe(dir);
    expect(calls[0]!.files).toEqual(["a.js", "new.py"]);
    expect(calls[0]!.opts.engines).toEqual(["opengrep", "gitleaks"]);
    expect(calls[0]!.opts.ignoreFile).toBe(join(dir, ".vigilignore"));
    await expect(readdir(calls[0]!.target)).rejects.toThrow(); // temp copy removed

    expect(body.scope).toBe("changed");
    expect(body.files).toEqual(["a.js", "new.py"]);
    expect(body.totals).toEqual({ critical: 1, low: 1 });
    expect(body.findings.map((f: any) => f.location)).toEqual(["new.py:2", "a.js:1"]); // severity order
    expect(body.warnings).toEqual([`warning in ${dir}/x`]); // temp path mapped back
    expect(JSON.stringify(body)).not.toContain("SECRET_CODE");
  });

  it("a changed manifest also runs the dependency engines on the real root", async () => {
    const dir = await repo();
    await writeFile(join(dir, "package.json"), '{"dependencies":{}}');
    const { body, calls } = await scanVia(dir, { offline: true });
    expect(calls.map((c) => [c.target === dir, c.opts.engines])).toEqual([
      [false, ["opengrep", "gitleaks"]],
      [true, ["osv-scanner", "pkgrisk"]],
    ]);
    expect(calls[1]!.opts.offline).toBe(true);
    expect(body.warnings[0]).toMatch(/dependency manifest changed/);
  });

  it("nothing changed: no engine runs", async () => {
    const dir = await repo();
    const { body, calls } = await scanVia(dir, {});
    expect(calls).toHaveLength(0);
    expect(body.findings).toEqual([]);
    expect(body.hint).toMatch(/scope "all"/);
  });

  it("scope all scans the root; limit truncates with a hint", async () => {
    const dir = await repo();
    const { body, calls } = await scanVia(dir, { scope: "all", limit: 1 });
    expect(calls[0]!.target).toBe(dir);
    expect(body.shown).toBe(1);
    expect(body.hint).toMatch(/more not shown/);
  });

  it("paths: confined to the root, symlinks included", async () => {
    const dir = await repo();
    const outside = await tempDir({ "secret.txt": "x" });
    await symlink(join(outside, "secret.txt"), join(dir, "link.txt"));
    for (const p of ["../x", join(outside, "secret.txt"), "link.txt", "nope.js"]) {
      const { res } = await scanVia(dir, { paths: [p] });
      expect(res.isError, p).toBe(true);
    }
    const { body, calls } = await scanVia(dir, { paths: ["b.js", "./b.js"] });
    expect(calls[0]!.files).toEqual(["b.js"]);
    expect(body.scope).toBe("paths");
  });

  it("rejects bad arguments and non-git roots for scope changed", async () => {
    const dir = await repo();
    for (const args of [{ scope: "x" }, { engines: ["nmap"] }, { limit: 0 }, { paths: "a.js" }]) {
      expect((await scanVia(dir, args)).res.isError, JSON.stringify(args)).toBe(true);
    }
    const plain = await tempDir({ "a.js": "x" });
    const { res, body } = await scanVia(plain, {});
    expect(res.isError).toBe(true);
    expect(body).toMatch(/not a git repository/);
  });

  it("explain returns the latest scan's finding without code", async () => {
    const dir = await repo();
    const f = finding("a.js", 3, "high", { dataflow: [{ path: "a.js", line: 1, snippet: "SECRET_CODE()" }] });
    const scan = async (): Promise<ScanResult> => ({ root: dir, findings: [f], ignores: [], warnings: [], engines: [] });
    const replies = await rpc(createTools(dir, { scan }), [call(1, "explain", { id: f.id })]);
    expect(replies[0]!.result.isError).toBe(true); // no scan yet

    const tools = createTools(dir, { scan });
    const input = new PassThrough();
    const output = new PassThrough();
    let out = "";
    output.on("data", (c) => (out += String(c)));
    const done = serve({ name: "v", version: "0" }, tools, { input, output });
    input.write(JSON.stringify(call(1, "scan", { scope: "all" })) + "\n");
    await new Promise((r) => setTimeout(r, 50));
    input.write(JSON.stringify(call(2, "explain", { id: f.id })) + "\n");
    input.end();
    await done;
    const explained = out.split("\n").filter(Boolean).map((l) => JSON.parse(l)).find((r) => r.id === 2)!;
    const body = JSON.parse(explained.result.content[0].text);
    expect(body).toMatchObject({ id: f.id, message: "what, why, fix", location: { path: "a.js", startLine: 3 }, dataflow: [{ path: "a.js", line: 1 }] });
    expect(body.cwe[0].url).toBe("https://cwe.mitre.org/data/definitions/89.html");
    expect(JSON.stringify(body)).not.toContain("SECRET_CODE");
  });
});

describe("check_package tool", () => {
  const NOW = Date.parse("2026-11-14T00:00:00Z");
  const old = { "dist-tags": { latest: "1.0.0" }, time: { created: "2015-01-01T00:00:00Z", "1.0.0": "2015-01-01T00:00:00Z" } };
  const fresh = { "dist-tags": { latest: "1.0.0" }, time: { created: "2026-11-12T00:00:00Z", "1.0.0": "2026-11-12T00:00:00Z" } };

  async function check(args: Record<string, unknown>, routes: Record<string, unknown>, failing = false) {
    const fetch: FetchLike = async (url) => {
      if (failing) throw new Error("offline");
      return url in routes ? new Response(JSON.stringify(routes[url]), { status: 200 }) : new Response("{}", { status: 404 });
    };
    const tools = createTools(".", { pkgrisk: { fetch, now: () => NOW, sleep: async () => {}, cacheDir: undefined } });
    const [reply] = await rpc(tools, [call(1, "check_package", args)]);
    const res = reply!.result;
    return res.isError ? { error: res.content[0].text as string } : JSON.parse(res.content[0].text);
  }
  const NPM = (n: string) => `https://registry.npmjs.org/${n}`;

  it("verdicts: ok, block (missing / typosquat), caution (brand-new), unverified", async () => {
    expect((await check({ ecosystem: "npm", name: "express" }, { [NPM("express")]: old })).verdict).toBe("ok");
    const missing = await check({ ecosystem: "npm", name: "react-auth-helperz-9x" }, {});
    expect(missing.verdict).toBe("block");
    expect(missing.findings[0].rule).toBe("pkg-nonexistent");
    const typo = await check({ ecosystem: "npm", name: "expresss" }, { [NPM("expresss")]: old });
    expect([typo.verdict, typo.findings[0].rule]).toEqual(["block", "pkg-typosquat"]);
    expect((await check({ ecosystem: "npm", name: "shiny-new-lib" }, { [NPM("shiny-new-lib")]: fresh })).verdict).toBe("caution");
    expect((await check({ ecosystem: "npm", name: "shiny-new-lib" }, {}, true)).verdict).toBe("unverified");
  });

  it("normalizes PyPI names and rejects bad input", async () => {
    const r = await check({ ecosystem: "pypi", name: "Flask_Login" }, { "https://pypi.org/pypi/flask-login/json": { info: { version: "1.0.0" }, releases: { "1.0.0": [{ upload_time_iso_8601: "2015-01-01T00:00:00Z", packagetype: "bdist_wheel" }] } } });
    expect(r.package).toBe("flask-login");
    expect(r.ecosystem).toBe("PyPI");
    for (const args of [{ ecosystem: "cargo", name: "x" }, { ecosystem: "npm" }, { ecosystem: "npm", name: "../etc" }]) {
      expect((await check(args, {})).error, JSON.stringify(args)).toBeDefined();
    }
  });
});

describe("vigil mcp over stdio", () => {
  it("answers initialize and tools/list from the real CLI", async () => {
    const msgs = [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {} } },
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
    ];
    const cli = join(import.meta.dirname, "..", "src", "cli.ts");
    const tsx = join(import.meta.dirname, "..", "node_modules", ".bin", "tsx");
    const child = execFile(tsx, [cli, "mcp", "."], { cwd: await tempDir() });
    let out = "";
    child.stdout!.on("data", (c) => (out += String(c)));
    child.stdin!.end(msgs.map((m) => JSON.stringify(m)).join("\n") + "\n");
    await new Promise((r) => child.on("close", r));
    const replies = out.split("\n").filter(Boolean).map((l) => JSON.parse(l)); // every stdout line is JSON-RPC
    expect(replies.map((r) => r.id)).toEqual([1, 2]);
    expect(replies[1].result.tools.map((t: any) => t.name)).toEqual(["scan", "explain", "check_package"]);
    await expect(readFile(cli, "utf8")).resolves.toContain('case "mcp"');
  }, 30_000);
});
