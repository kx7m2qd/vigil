/**
 * Static import extraction for JS/TS and Python. Regex-based on purpose: it only has to answer
 * "is package X imported anywhere?", and every mistake it makes must lean towards "imported"
 * (a wrong "unreachable" hides real risk; a wrong "reachable" only costs noise). So comments and
 * strings that look like imports count as imports.
 */

export interface ImportHit {
  /** npm package name (`@scope/name` or `name`) or Python top-level module. */
  name: string;
  line: number;
}

export interface FileImports {
  imports: ImportHit[];
  /** Line of an import whose target is computed at runtime (`require(x)`, `import_module(x)`). */
  dynamicLine?: number;
}

const lineAt = (text: string, index: number): number => {
  let n = 1;
  for (let i = text.indexOf("\n"); i !== -1 && i < index; i = text.indexOf("\n", i + 1)) n++;
  return n;
};

/** `lodash/merge` → `lodash`, `@a/b/c` → `@a/b`; relative, absolute, URL and builtin specifiers → undefined. */
export function npmPackageOf(spec: string): string | undefined {
  if (!spec || /^[./~#]/.test(spec) || /^[a-z][a-z0-9+.-]*:/i.test(spec)) return undefined; // ./x, /x, node:fs, https:
  const parts = spec.split("/");
  if (spec.startsWith("@")) return parts.length >= 2 && parts[1] ? `${parts[0]}/${parts[1]}` : undefined;
  return parts[0] || undefined;
}

// from 'x' · import 'x' · import('x') · require('x') · require.resolve('x') · export … from 'x'
const JS_STATIC = /(?:\bfrom|\bimport|\brequire(?:\.resolve)?)\s*\(?\s*(['"`])([^'"`\n]+)\1/g;
// A call whose argument is not a plain string literal, or is a template that starts with `${`.
const JS_DYNAMIC = /\b(?:require|import)\s*\(\s*(?!['")]|`(?!\$\{))/g;

export function jsImports(text: string): FileImports {
  const imports: ImportHit[] = [];
  for (const m of text.matchAll(JS_STATIC)) {
    const spec = m[2] as string;
    if (spec.startsWith("${")) continue;
    const name = npmPackageOf(spec);
    if (name) imports.push({ name, line: lineAt(text, m.index) });
  }
  let dynamicLine: number | undefined;
  for (const m of text.matchAll(JS_DYNAMIC)) {
    // `function require(` / `.import(` method definitions are not dynamic imports.
    const before = text.slice(Math.max(0, m.index - 10), m.index);
    if (/(?:function\s+|\.)$/.test(before)) continue;
    dynamicLine = lineAt(text, m.index);
    break;
  }
  return dynamicLine === undefined ? { imports } : { imports, dynamicLine };
}

const PY_FROM = /^[ \t]*from[ \t]+([A-Za-z_][\w.]*)[ \t]+import\b/gm;
const PY_IMPORT = /^[ \t]*import[ \t]+([A-Za-z_][\w.]*(?:[ \t]*(?:as[ \t]+\w+)?[ \t]*,[ \t]*[A-Za-z_][\w.]*)*)/gm;
const PY_LITERAL_CALL = /\b(?:importlib\.import_module|import_module|__import__)\s*\(\s*(['"])([A-Za-z_][\w.]*)\1/g;
const PY_DYNAMIC = /\b(?:importlib\.import_module|import_module|__import__)\s*\(\s*(?!['"])/g;

export function pyImports(text: string): FileImports {
  const imports: ImportHit[] = [];
  const top = (dotted: string) => dotted.split(".")[0] as string;
  for (const m of text.matchAll(PY_FROM)) imports.push({ name: top(m[1] as string), line: lineAt(text, m.index) });
  for (const m of text.matchAll(PY_IMPORT)) {
    const line = lineAt(text, m.index);
    for (const part of (m[1] as string).split(",")) {
      const mod = part.trim().split(/\s+/)[0];
      if (mod) imports.push({ name: top(mod), line });
    }
  }
  for (const m of text.matchAll(PY_LITERAL_CALL)) imports.push({ name: top(m[2] as string), line: lineAt(text, m.index) });
  const dyn = PY_DYNAMIC.exec(text);
  PY_DYNAMIC.lastIndex = 0;
  return dyn ? { imports, dynamicLine: lineAt(text, dyn.index) } : { imports };
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * First line where `word` appears as a whole token. `/` may precede it so paths like
 * `/usr/bin/gunicorn` or `node_modules/.bin/vite` still count (over-matching is the safe side).
 * Not counted: right after a `.` (`~/.npm`, `app.py`), or as the first segment of an absolute
 * path that continues (`/tmp/x`): those name files and directories, not packages.
 */
export function findToken(text: string, word: string): number | undefined {
  const re = new RegExp(`(?<![\\w@.-])${escapeRe(word)}(?![\\w-])`, "g");
  for (const m of text.matchAll(re)) {
    const before = text.slice(Math.max(0, m.index - 2), m.index);
    const after = text[m.index + word.length];
    if (after === "/" && /(?:^|[\s"'=:(~])\/$/.test(m.index === 1 ? ` ${before}` : before)) continue;
    return lineAt(text, m.index);
  }
  return undefined;
}
