/**
 * Python imports read with Python's own parser (`ast`), run through the local `python3`. More exact
 * than the regex in imports.ts: an `import x` inside a docstring or comment doesn't count.
 * Files Python can't parse (Python 2, newer syntax than the local interpreter) and machines without
 * python3 fall back to the regex, so this can only refine results, never lose them.
 *
 * Runs `python3 -I` (isolated: ignores PYTHON* env vars and the current directory, so a project
 * file named `ast.py` can't be imported). It parses files; it never executes them.
 */
import { spawn } from "node:child_process";
import type { FileImports } from "./imports.js";

const SCRIPT = String.raw`
import ast, json, sys
out = {}
for path in json.load(sys.stdin):
    try:
        with open(path, "rb") as fh:
            src = fh.read(1000001)
        if len(src) > 1000000:
            continue
        tree = ast.parse(src)
    except Exception:
        continue
    imps, dyn = [], None
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                imps.append([a.name.split(".")[0], n.lineno])
        elif isinstance(n, ast.ImportFrom):
            if n.level == 0 and n.module:
                imps.append([n.module.split(".")[0], n.lineno])
        elif isinstance(n, ast.Call):
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else None)
            if name in ("import_module", "__import__") and n.args:
                a = n.args[0]
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    if a.value and not a.value.startswith("."):
                        imps.append([a.value.split(".")[0], n.lineno])
                elif dyn is None or n.lineno < dyn:
                    dyn = n.lineno
    out[path] = [imps, dyn]
json.dump(out, sys.stdout)
`;

const TIMEOUT_MS = 60_000;

/**
 * Absolute path → imports, for every file Python parsed. Files missing from the map must be read
 * with the regex fallback. Never throws.
 */
export async function pythonAstImports(paths: string[], python = "python3"): Promise<Map<string, FileImports>> {
  const result = new Map<string, FileImports>();
  if (!paths.length) return result;
  const raw = await new Promise<string | undefined>((resolve) => {
    let out = "";
    let done = false;
    const finish = (v: string | undefined) => {
      if (!done) {
        done = true;
        resolve(v);
      }
    };
    let child;
    try {
      child = spawn(python, ["-I", "-c", SCRIPT], { stdio: ["pipe", "pipe", "ignore"] });
    } catch {
      return finish(undefined);
    }
    const timer = setTimeout(() => {
      child.kill();
      finish(undefined);
    }, TIMEOUT_MS);
    child.on("error", () => finish(undefined));
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (d: string) => (out += d));
    child.on("close", (code) => {
      clearTimeout(timer);
      finish(code === 0 ? out : undefined);
    });
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(paths));
  });
  if (!raw) return result;
  try {
    const parsed = JSON.parse(raw) as Record<string, [[string, number][], number | null]>;
    for (const [path, [imps, dyn]] of Object.entries(parsed)) {
      const imports = imps.map(([name, line]) => ({ name, line }));
      result.set(path, dyn === null ? { imports } : { imports, dynamicLine: dyn });
    }
  } catch {
    // Unreadable output: everything falls back to the regex.
  }
  return result;
}
