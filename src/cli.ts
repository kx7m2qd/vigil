#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { gateSeverity, SEVERITY_ORDER, severityAtLeast, type EngineName, type Severity } from "./core/finding.js";
import { enginePath, installEngine, isInstalled, resolveEngine } from "./engines/install.js";
import { BINARY_ENGINES, ENGINES } from "./engines/manifest.js";
import { RULES_DIR } from "./engines/opengrep.js";
import { run } from "./engines/run.js";
import { install, uninstall } from "./hook/install.js";
import { hookRun } from "./hook/run.js";
import { serve } from "./mcp/protocol.js";
import { createTools, INSTRUCTIONS } from "./mcp/tools.js";
import { toSarif } from "./report/sarif.js";
import { toText } from "./report/text.js";
import { ALL_ENGINES, scan } from "./scan.js";
import { TOOL_NAME, TOOL_VERSION } from "./version.js";

const HELP = `${TOOL_NAME} ${TOOL_VERSION} — local-first application security scanner

Usage:
  ${TOOL_NAME} scan [path]          Scan code, dependencies and secrets (default path: .)
      --format text|json|sarif     Output format (default: text)
      --output <file>              Write the report to a file instead of stdout
      --fail-on <severity|none>    Exit 1 if a finding is at least this severe (default: high)
      --engines <list>             Comma-separated subset of: ${ALL_ENGINES.join(", ")}
      --no-install                 Do not auto-install missing engines
      --offline                    Turn off the pkgrisk network checks (registry lookups). Typosquat,
                                   install-script and known-malicious checks still run.
      --no-reachability            Skip the reachability check. By default, vulnerable dependencies
                                   that nothing in the project uses are shown one severity level
                                   lower, but still fail --fail-on at their original severity.
      --trust-reachability         Let --fail-on use the lowered severity of unreachable findings
      --reachable-only             Hide unreachable findings entirely (implies --trust-reachability)
      --ignore-file <file>         Read ignore patterns from this file instead of <path>/.vigilignore
                                   (CI: pass the base branch's copy so a PR can't un-scan its own code)

  pkgrisk (dependency supply-chain checks) sends package names and versions, nothing else, to
  registry.npmjs.org and pypi.org (osv-scanner already sends the same to osv.dev). Source code, file
  paths and manifest contents never leave your machine. Use --offline to send nothing.

  ${TOOL_NAME} engines install      Download and verify the pinned engine binaries
  ${TOOL_NAME} engines status       Show which engines are installed
  ${TOOL_NAME} hook install [--force]  Install a git pre-commit hook. It scans staged content (the
                                    index) with opengrep + gitleaks and only reports added lines.
                                    Secrets always block; other findings block at --fail-on.
  ${TOOL_NAME} hook uninstall       Remove the hook (only if vigil wrote it; restores a backed-up hook)
  ${TOOL_NAME} hook run [--fail-on <severity|none>]
                                    What the hook calls (default: high). Exit 1 blocked, 2 engine
                                    missing (fail closed). Dependency checks: use \`${TOOL_NAME} scan\` in CI.
                                    Bypass once: git commit with the no-verify flag.
  ${TOOL_NAME} mcp [path]           MCP server on stdio for coding agents (tools: scan, explain,
                                  check_package). Confined to [path] (default: .). Add to Claude Code:
                                  claude mcp add vigil -- npx -y @kx7m2qd/vigil mcp
  ${TOOL_NAME} test-rules           Run the rule test suite (rules/**)

Exit codes: 0 clean · 1 findings at or above --fail-on · 2 usage or engine error
`;

function fail(message: string): never {
  process.stderr.write(`${TOOL_NAME}: ${message}\n`);
  process.exit(2);
}

function parseEngines(value: string | undefined): EngineName[] | undefined {
  if (!value) return undefined;
  const list = value.split(",").map((s) => s.trim());
  for (const e of list) if (!ALL_ENGINES.includes(e as EngineName)) fail(`unknown engine "${e}"`);
  return list as EngineName[];
}

async function cmdScan(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      format: { type: "string", default: "text" },
      output: { type: "string" },
      "fail-on": { type: "string", default: "high" },
      engines: { type: "string" },
      "no-install": { type: "boolean", default: false },
      offline: { type: "boolean", default: false },
      "reachable-only": { type: "boolean", default: false },
      "no-reachability": { type: "boolean", default: false },
      "trust-reachability": { type: "boolean", default: false },
      "ignore-file": { type: "string" },
    },
  });
  const format = values.format;
  if (format !== "text" && format !== "json" && format !== "sarif") fail(`unknown format "${format}"`);
  const failOn = values["fail-on"];
  if (failOn !== "none" && !SEVERITY_ORDER.includes(failOn as Severity)) fail(`unknown severity "${failOn}"`);

  const result = await scan(positionals[0] ?? ".", {
    engines: parseEngines(values.engines),
    autoInstall: !values["no-install"],
    offline: values.offline,
    reachability: !values["no-reachability"],
    reachableOnly: values["reachable-only"],
    ignoreFile: values["ignore-file"],
  });

  const report =
    format === "json"
      ? JSON.stringify(result, null, 2)
      : format === "sarif"
        ? JSON.stringify(toSarif(result), null, 2)
        : toText(result, { color: !values.output && process.stdout.isTTY === true });

  if (values.output) {
    await writeFile(values.output, report + "\n");
    process.stderr.write(`${TOOL_NAME}: wrote ${result.findings.length} findings to ${values.output}\n`);
  } else {
    process.stdout.write(report + "\n");
  }
  if (format !== "text") for (const w of result.warnings) process.stderr.write(`warning: ${w}\n`);

  if (result.engines.some((e) => !e.ok)) return 2;
  const trust = values["trust-reachability"];
  if (failOn !== "none" && result.findings.some((f) => severityAtLeast(gateSeverity(f, trust), failOn as Severity))) return 1;
  return 0;
}

async function cmdEngines(args: string[]): Promise<number> {
  const sub = args[0];
  if (sub === "status") {
    for (const name of BINARY_ENGINES) {
      const ok = await isInstalled(name);
      process.stdout.write(`${name.padEnd(12)} ${ENGINES[name].version.padEnd(8)} ${ok ? enginePath(name) : "not installed"}\n`);
    }
    return 0;
  }
  if (sub === "install") {
    for (const name of BINARY_ENGINES) {
      if (await isInstalled(name)) {
        process.stdout.write(`${name}: already installed\n`);
        continue;
      }
      process.stdout.write(`${name}: downloading ${ENGINES[name].version}… `);
      const path = await installEngine(name);
      process.stdout.write(`verified → ${path}\n`);
    }
    return 0;
  }
  fail(`usage: ${TOOL_NAME} engines install|status`);
}

async function cmdHook(args: string[]): Promise<number> {
  const [sub, ...rest] = args;
  if (sub === "install") {
    const { values } = parseArgs({ args: rest, options: { force: { type: "boolean", default: false } } });
    const res = await install({ force: values.force });
    (res.code === 0 ? process.stdout : process.stderr).write(`${TOOL_NAME}: ${res.message}\n`);
    return res.code;
  }
  if (sub === "uninstall") {
    parseArgs({ args: rest, options: {} });
    const res = await uninstall();
    (res.code === 0 ? process.stdout : process.stderr).write(`${TOOL_NAME}: ${res.message}\n`);
    return res.code;
  }
  if (sub === "run") {
    const { values } = parseArgs({
      args: rest,
      allowPositionals: true,
      options: { "fail-on": { type: "string", default: "high" } },
    });
    const failOn = values["fail-on"];
    if (failOn !== "none" && !SEVERITY_ORDER.includes(failOn as Severity)) fail(`unknown severity "${failOn}"`);
    const res = await hookRun({ failOn: failOn as Severity | "none", color: process.stderr.isTTY === true });
    if (res.output) process.stderr.write(res.output);
    return res.code;
  }
  fail(`usage: ${TOOL_NAME} hook install|uninstall|run`);
}

async function cmdTestRules(): Promise<number> {
  const bin = await resolveEngine("opengrep", { autoInstall: true });
  const res = await run(bin, ["test", RULES_DIR]);
  process.stdout.write(res.stdout);
  process.stderr.write(res.stderr);
  return res.code;
}

async function cmdMcp(args: string[]): Promise<number> {
  const { positionals } = parseArgs({ args, allowPositionals: true, options: {} });
  if (positionals.length > 1) fail(`usage: ${TOOL_NAME} mcp [path]`);
  // stdout is the protocol channel: everything else goes to stderr.
  await serve({ name: TOOL_NAME, version: TOOL_VERSION, instructions: INSTRUCTIONS }, createTools(positionals[0] ?? "."), {
    input: process.stdin,
    output: process.stdout,
    log: (line) => process.stderr.write(`${TOOL_NAME} mcp: ${line}\n`),
  });
  return 0;
}

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  switch (command) {
    case "scan":
      return cmdScan(rest);
    case "engines":
      return cmdEngines(rest);
    case "hook":
      return cmdHook(rest);
    case "mcp":
      return cmdMcp(rest);
    case "test-rules":
      return cmdTestRules();
    case "--version":
    case "-v":
      process.stdout.write(`${TOOL_VERSION}\n`);
      return 0;
    case undefined:
    case "help":
    case "--help":
    case "-h":
      process.stdout.write(HELP);
      return 0;
    default:
      fail(`unknown command "${command}". Run \`${TOOL_NAME} --help\`.`);
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e: unknown) => fail(e instanceof Error ? e.message : String(e)),
);
