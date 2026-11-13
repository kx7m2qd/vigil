/**
 * Regression tests for Vigil's own security properties (docs/SECURITY.md).
 * If one of these fails, a hole has been reopened: do not loosen the test.
 */
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { redactSecret, redactStringLiterals, secretDigest } from "../src/core/finding.js";
import { hasUnsafeChars, sanitizeForTerminal } from "../src/core/sanitize.js";
import { enginePath, isInstalled, resolveEngine } from "../src/engines/install.js";
import { describeError, normalizeOpengrep } from "../src/engines/opengrep.js";
import { engineEnv } from "../src/engines/run.js";
import { toText } from "../src/report/text.js";
import { scan } from "../src/scan.js";

const ESC = String.fromCharCode(0x1b);
const BEL = String.fromCharCode(0x07);
const RLO = String.fromCharCode(0x202e);
// Built at runtime so no token-shaped string is committed to the repo.
const FAKE_TOKEN = ["ghp", "_", "R4nd0mT0k3nV4lu3ThatIsLong1234567890"].join("");

describe("terminal output", () => {
  it("strips escape sequences and bidi controls", () => {
    const hostile = `exec("ls ${ESC}]52;c;ZXZpbA==${BEL}${ESC}[2J" ${RLO}x)`;
    const out = sanitizeForTerminal(hostile);
    expect(out).not.toContain(ESC);
    expect(out).not.toContain(BEL);
    expect(out).not.toContain(RLO);
  });

  it("toText never emits a control character from a finding", () => {
    const text = toText(
      {
        root: "/r",
        ignores: [`x${ESC}[2J`],
        warnings: [`w${ESC}]8;;http://evil${BEL}`],
        engines: [],
        findings: [
          {
            id: "1",
            category: "code",
            engine: "opengrep",
            ruleId: "r",
            title: `t${ESC}[31m`,
            message: `m${ESC}[2J`,
            severity: "high",
            location: { path: `p${RLO}.js`, startLine: 1, snippet: `s${ESC}]52;c;AA==${BEL}` },
            cwe: [],
            owasp: [],
          },
        ],
      },
      { color: false },
    );
    expect(text).not.toContain(ESC);
    expect(text).not.toContain(BEL);
    expect(text).not.toContain(RLO);
  });
});

describe("secret handling", () => {
  it("fully masks short secrets and hides length of long ones", () => {
    expect(redactSecret("hunter2pass")).toBe("********");
    expect(redactSecret(FAKE_TOKEN)).toBe(redactSecret(FAKE_TOKEN + "abcdef"));
  });

  it("redacts string literals in code excerpts", () => {
    const out = redactStringLiterals(`jwt.sign(p, "super-secret-signing-key", 'abc\\'def', \`tmpl\`)`);
    expect(out).not.toContain("secret-signing");
    expect(out).not.toContain("abc");
  });

  it("secret fingerprints are not a plain SHA-256 of the secret", () => {
    const fast = createHash("sha256").update("password1").digest("hex");
    expect(secretDigest("password1")).not.toBe(fast);
    expect(secretDigest("password1")).toBe(secretDigest("password1"));
  });

  it("opengrep findings from credential rules never contain the secret", () => {
    const secret = "my-very-secret-signing-key";
    const findings = normalizeOpengrep("/r", {
      errors: [],
      results: [
        {
          check_id: "js-jwt-hardcoded-secret",
          path: "/r/a.js",
          start: { line: 1, col: 1 },
          end: { line: 1, col: 40 },
          extra: {
            message: "m",
            severity: "ERROR",
            lines: `jwt.sign(p, "${secret}")`,
            metadata: { cwe: ["CWE-798: Use of Hard-coded Credentials"] },
            dataflow_trace: {
              taint_source: ["CliLoc", [{ path: "/r/a.js", start: { line: 1, col: 1 }, end: { line: 1, col: 9 } }, `"${secret}"`]],
            },
          },
        },
      ],
    });
    expect(JSON.stringify(findings)).not.toContain(secret);
  });

  it("engine errors about a file do not echo its source", () => {
    const w = describeError("/r", { type: ["PartialParsing"], path: "/r/a.js", message: `x = "${FAKE_TOKEN}"` });
    expect(w).not.toContain(FAKE_TOKEN);
    expect(w).toContain("a.js");
  });
});

describe("engine processes", () => {
  it("do not inherit credentials or engine config from the environment", () => {
    const env = engineEnv({
      PATH: "/bin",
      GITHUB_TOKEN: "x",
      ANTHROPIC_API_KEY: "x",
      AWS_SECRET_ACCESS_KEY: "x",
      GITLEAKS_CONFIG: "/evil.toml",
      GITLEAKS_CONFIG_TOML: "[allowlist]",
      SEMGREP_RULES: "x",
    });
    expect(env).toEqual({ PATH: "/bin" });
  });
});

describe("engine binaries", () => {
  const saved = process.env.VIGIL_HOME;
  afterEach(() => {
    if (saved === undefined) delete process.env.VIGIL_HOME;
    else process.env.VIGIL_HOME = saved;
  });

  it("a tampered cached binary is reported as not installed and never resolved", async () => {
    process.env.VIGIL_HOME = await mkdtemp(join(tmpdir(), "vigil-home-"));
    const path = enginePath("gitleaks");
    await mkdir(join(path, ".."), { recursive: true });
    await writeFile(path, "#!/bin/sh\necho pwned\n", { mode: 0o755 });
    expect(await isInstalled("gitleaks")).toBe(false);
    await expect(resolveEngine("gitleaks", { autoInstall: false })).rejects.toThrow(/checksum/);
  });
});

describe("source hygiene", () => {
  it("our own code contains no bidi or control characters (Trojan Source)", async () => {
    const roots = ["src", "test", "bench", "rules", "config"];
    const bad: string[] = [];
    for (const root of roots) {
      for (const e of await readdir(root, { recursive: true, withFileTypes: true })) {
        if (!e.isFile()) continue;
        const file = join(e.parentPath, e.name);
        if (hasUnsafeChars(await readFile(file, "utf8"))) bad.push(file);
      }
    }
    expect(bad).toEqual([]);
  });
});

// End-to-end: a hostile repo tries every engine-level way to hide its own findings.
const enginesReady = (await Promise.all((["opengrep", "gitleaks", "osv-scanner"] as const).map(isInstalled))).every(Boolean);

describe.skipIf(!enginesReady)("hostile repo cannot suppress findings", () => {
  it("ignores nosemgrep, .semgrepignore, gitleaks:allow, .gitleaks.toml, .gitleaksignore, osv-scanner.toml", async () => {
    const repo = await mkdtemp(join(tmpdir(), "vigil-hostile-"));
    const files: Record<string, string> = {
      "app.js": `const { exec } = require("child_process");\nmodule.exports = (req, res) => {\n  exec("ls " + req.query.dir); // nosemgrep\n};\n`,
      "token.js": `const t = "${FAKE_TOKEN}"; // gitleaks:allow\n`,
      ".semgrepignore": "app.js\n",
      ".gitleaks.toml": `[allowlist]\npaths = [".*"]\n`,
      ".gitleaksignore": "token.js:github-pat:1\n",
      "osv-scanner.toml": `[[PackageOverrides]]\nname = "lodash"\nignore = true\n`,
      "package-lock.json": JSON.stringify({
        name: "h",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": { name: "h", dependencies: { lodash: "4.17.20" } },
          "node_modules/lodash": { version: "4.17.20", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz" },
        },
      }),
    };
    for (const [name, body] of Object.entries(files)) await writeFile(join(repo, name), body);

    const result = await scan(repo, { autoInstall: false, offline: true });
    expect(result.engines.every((e) => e.ok)).toBe(true);
    const rules = new Set(result.findings.map((f) => f.ruleId));
    expect(rules).toContain("js-command-injection");
    expect(rules).toContain("github-pat");
    expect(result.warnings.some((w) => w.includes(".gitleaksignore"))).toBe(true);
    expect(result.findings.some((f) => f.dependency?.name === "lodash")).toBe(true);
    expect(JSON.stringify(result)).not.toContain(FAKE_TOKEN);
  }, 180_000);
});
