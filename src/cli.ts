#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { SEVERITY_ORDER, severityAtLeast, type EngineName, type Severity } from "./core/finding.js";
import { enginePath, installEngine, isInstalled, resolveEngine } from "./engines/install.js";
import { ENGINES } from "./engines/manifest.js";
import { RULES_DIR } from "./engines/opengrep.js";
import { run } from "./engines/run.js";
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
  ${TOOL_NAME} engines install      Download and verify the pinned engine binaries
  ${TOOL_NAME} engines status       Show which engines are installed
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
    },
  });
  const format = values.format;
  if (format !== "text" && format !== "json" && format !== "sarif") fail(`unknown format "${format}"`);
  const failOn = values["fail-on"];
  if (failOn !== "none" && !SEVERITY_ORDER.includes(failOn as Severity)) fail(`unknown severity "${failOn}"`);

  const result = await scan(positionals[0] ?? ".", {
    engines: parseEngines(values.engines),
    autoInstall: !values["no-install"],
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
  if (failOn !== "none" && result.findings.some((f) => severityAtLeast(f.severity, failOn as Severity))) return 1;
  return 0;
}

async function cmdEngines(args: string[]): Promise<number> {
  const sub = args[0];
  if (sub === "status") {
    for (const name of ALL_ENGINES) {
      const ok = await isInstalled(name);
      process.stdout.write(`${name.padEnd(12)} ${ENGINES[name].version.padEnd(8)} ${ok ? enginePath(name) : "not installed"}\n`);
    }
    return 0;
  }
  if (sub === "install") {
    for (const name of ALL_ENGINES) {
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

async function cmdTestRules(): Promise<number> {
  const bin = await resolveEngine("opengrep", { autoInstall: true });
  const res = await run(bin, ["test", RULES_DIR]);
  process.stdout.write(res.stdout);
  process.stderr.write(res.stderr);
  return res.code;
}

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  switch (command) {
    case "scan":
      return cmdScan(rest);
    case "engines":
      return cmdEngines(rest);
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
