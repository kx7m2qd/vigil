import { spawn } from "node:child_process";

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface RunOptions {
  cwd?: string;
  /** Kill the process after this long. Default: 20 minutes. */
  timeoutMs?: number;
}

/**
 * Environment variables passed through to engines. Everything else (CI tokens,
 * API keys, GITLEAKS_CONFIG, SEMGREP_*, ...) is dropped so a scanned repo's CI
 * environment cannot reconfigure an engine and engines never see credentials.
 */
const ENV_ALLOW = [
  "PATH",
  "HOME",
  "TMPDIR",
  "TEMP",
  "TMP",
  "LANG",
  "LC_ALL",
  "TERM",
  "SYSTEMROOT",
  "HTTPS_PROXY",
  "https_proxy",
  "HTTP_PROXY",
  "http_proxy",
  "NO_PROXY",
  "no_proxy",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
];

export function engineEnv(source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const k of ENV_ALLOW) if (source[k] !== undefined) env[k] = source[k];
  return env;
}

/** Run a command without a shell and collect its output. */
export function run(cmd: string, args: string[], opts: RunOptions = {}): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: engineEnv(),
      stdio: ["ignore", "pipe", "pipe"],
      timeout: opts.timeoutMs ?? 20 * 60_000,
      killSignal: "SIGKILL",
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (d: Buffer) => out.push(d));
    child.stderr.on("data", (d: Buffer) => err.push(d));
    child.on("error", reject);
    child.on("close", (code, signal) => {
      if (signal) return reject(new Error(`${cmd} was killed (${signal}); it ran past its time limit`));
      resolve({
        code: code ?? 1,
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
      });
    });
  });
}
