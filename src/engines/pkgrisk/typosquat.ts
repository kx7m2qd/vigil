/**
 * Typosquat matching against the popular-package lists. Pure and offline.
 * Accuracy over coverage: a name is flagged only when it is NOT popular itself and is
 * confusably close to a name that is.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { normalizePypi, type Ecosystem } from "./manifests.js";

export type MatchKind = "distance" | "separator" | "confusable";
export interface TyposquatMatch {
  target: string;
  kind: MatchKind;
}

/** Optimal-string-alignment (Damerau-Levenshtein with adjacent transpositions). Returns max+1 if above max. */
export function damerauLevenshtein(a: string, b: string, max = Infinity): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const la = a.length;
  const lb = b.length;
  let prev2: number[] = [];
  let prev: number[] = Array.from({ length: lb + 1 }, (_, j) => j);
  for (let i = 1; i <= la; i++) {
    const cur: number[] = [i];
    let rowMin = i;
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min((prev[j] as number) + 1, (cur[j - 1] as number) + 1, (prev[j - 1] as number) + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, (prev2[j - 2] as number) + 1);
      cur[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;
    prev2 = prev;
    prev = cur;
  }
  return prev[lb] as number;
}

/** Name with scope marker, separators and case removed: `@types/node` and `types-node` collide. */
export function squash(name: string): string {
  return name.toLowerCase().replace(/^@/, "").replace(/[-_./]/g, "");
}

/** Fold look-alike characters (`I`/`1`/`l`, `0`/`o`, `rn`/`m`, `vv`/`w`). */
export function foldConfusables(name: string): string {
  return name
    .toLowerCase()
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/[1i|]/g, "l")
    .replace(/0/g, "o");
}

const MIN_LEN = 5; // separator/scope matches need this many characters
const MIN_DIST_LEN = 6; // distance matches: shorter names are mostly different real words (utile/utila, error/verror)
const LONG_LEN = 10; // names this long may differ by 2

/**
 * Is `a` vs `b` plausibly a typo, rather than two real siblings (`listr`/`listr2`,
 * `prompt`/`prompts`, `lodash.get`/`lodash.set`, `@types/ws`/`@types/jws`)?
 */
export function plausibleTypo(a: string, b: string): boolean {
  const [short, long] = a.length <= b.length ? [a, b] : [b, a];
  if (a.replace(/\d/g, "") === b.replace(/\d/g, "")) {
    // Version siblings (listr/listr2, pyqt5/pyqt6, rfc3339/rfc3986) are not typos. A digit run
    // inserted mid-name (python-dateutil → python3-dateutil) is a known squat shape.
    const m = /^(.*?)(\d+)(.*)$/.exec(long);
    return m !== null && m[3] !== "" && `${m[1]}${m[3]}` === short;
  }
  // Plural siblings (prompt/prompts) are not typos — but a doubled final "s" (express → expresss) is.
  if (long.length === short.length + 1 && long === `${short}s` && !short.endsWith("s")) return false;
  const ta = a.split(/[-_./@]+/).filter(Boolean);
  const tb = b.split(/[-_./@]+/).filter(Boolean);
  if (ta.length === tb.length) {
    const diff = ta.map((t, i) => [t, tb[i] as string] as const).filter(([x, y]) => x !== y);
    // An edit inside one short word swaps it for another word, it is not a slip of the finger.
    if (diff.length === 1 && Math.min(diff[0]![0].length, diff[0]![1].length) < 5) return false;
  }
  return true;
}

export class PopularIndex {
  private readonly set: Set<string>;
  private readonly byLen = new Map<number, string[]>();
  private readonly bySquash = new Map<string, string>();
  private readonly byFold = new Map<string, string>();
  private readonly rank = new Map<string, number>();

  constructor(
    names: string[],
    private readonly eco: Ecosystem,
  ) {
    this.set = new Set(names);
    names.forEach((n, i) => {
      this.rank.set(n, i);
      const bucket = this.byLen.get(n.length) ?? [];
      bucket.push(n);
      this.byLen.set(n.length, bucket);
      if (!this.bySquash.has(squash(n))) this.bySquash.set(squash(n), n);
      if (!this.byFold.has(foldConfusables(n))) this.byFold.set(foldConfusables(n), n);
    });
  }

  has(name: string): boolean {
    return this.set.has(this.norm(name));
  }

  get size(): number {
    return this.set.size;
  }

  private norm(name: string): string {
    return this.eco === "PyPI" ? normalizePypi(name) : name.toLowerCase();
  }

  /** The popular name `name` imitates, or undefined. Popular names never match. */
  match(raw: string): TyposquatMatch | undefined {
    const name = this.norm(raw);
    if (this.set.has(name)) return undefined;

    // Separator / scope confusion: crossenv vs cross-env, types-node vs @types/node.
    const sq = squash(name);
    if (sq.length >= MIN_LEN) {
      const t = this.bySquash.get(sq);
      if (t && t !== name) return { target: t, kind: "separator" };
    }

    if (name.length < MIN_DIST_LEN) return undefined;
    const fold = this.byFold.get(foldConfusables(name));
    if (fold && fold !== name && squash(fold).length >= MIN_DIST_LEN) return { target: fold, kind: "confusable" };

    const max = name.length >= LONG_LEN ? 2 : 1;
    let best: { target: string; d: number; rank: number } | undefined;
    for (let len = name.length - max; len <= name.length + max; len++) {
      for (const t of this.byLen.get(len) ?? []) {
        if (t.length < MIN_DIST_LEN) continue;
        const d = damerauLevenshtein(name, t, max);
        if (d > max || !plausibleTypo(name, t)) continue;
        // Distance 2 only counts when the shorter name is itself long.
        if (d === 2 && Math.min(name.length, t.length) < LONG_LEN) continue;
        const rank = this.rank.get(t) ?? Infinity;
        if (!best || d < best.d || (d === best.d && rank < best.rank)) best = { target: t, d, rank };
      }
    }
    return best ? { target: best.target, kind: "distance" } : undefined;
  }
}

export interface AllowEntry {
  name: string;
  reason: string;
}

export interface TyposquatData {
  npm: PopularIndex;
  PyPI: PopularIndex;
  allow: Record<Ecosystem, Set<string>>;
}

const DATA_DIR = fileURLToPath(new URL("../../../data/", import.meta.url));

function readJson<T>(file: string, fallback: T): T {
  try {
    return JSON.parse(readFileSync(DATA_DIR + file, "utf8")) as T;
  } catch {
    return fallback;
  }
}

/** One name per line (see scripts/fetch-popular.ts for why not JSON). */
function readList(file: string): string[] {
  try {
    return readFileSync(DATA_DIR + file, "utf8").split("\n").map((l) => l.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

let cached: TyposquatData | undefined;

/** Load the committed lists (`npm run data:popular`) and the allow-list. Read once. */
export function loadTyposquatData(): TyposquatData {
  if (cached) return cached;
  const allow = readJson<Partial<Record<Ecosystem, AllowEntry[]>>>("typosquat-allow.json", {});
  cached = {
    npm: new PopularIndex(readList("popular-npm.txt"), "npm"),
    PyPI: new PopularIndex(readList("popular-pypi.txt"), "PyPI"),
    allow: {
      npm: new Set((allow.npm ?? []).map((e) => e.name.toLowerCase())),
      PyPI: new Set((allow.PyPI ?? []).map((e) => normalizePypi(e.name))),
    },
  };
  return cached;
}

export function isAllowed(data: TyposquatData, eco: Ecosystem, name: string): boolean {
  return data.allow[eco].has(eco === "PyPI" ? normalizePypi(name) : name.toLowerCase());
}
