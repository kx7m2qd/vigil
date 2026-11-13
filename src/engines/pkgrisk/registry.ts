/**
 * Registry lookups (npm, PyPI) with a small on-disk cache. The `fetch` is injectable so
 * tests and the bench never touch the network.
 *
 * What is sent: a package name in the URL path and a `vigil/<version>` User-Agent. Nothing
 * else (no source, no paths, no manifest content).
 */
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { TOOL_NAME, TOOL_VERSION } from "../../version.js";
import type { Ecosystem } from "./manifests.js";

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

/** Only the fields pkgrisk uses. */
export interface RegistryRecord {
  /** 200 = exists, 404 = not found. */
  status: 200 | 404;
  fetchedAt: number;
  /** First publish date. Never moves later once recorded. */
  created?: string;
  latest?: string;
  /** version → first publish time. */
  times?: Record<string, string>;
  /** PyPI: versions that only have an sdist (setup.py runs at install). */
  sdistOnly?: string[];
}

export interface Lookup {
  record?: RegistryRecord;
  /** Set when the registry could not be reached or answered unexpectedly. */
  error?: string;
}

export interface RegistryOptions {
  fetch?: FetchLike;
  now?: () => number;
  /** Where cached records live. Omit to disable the cache. */
  cacheDir?: string;
  sleep?: (ms: number) => Promise<void>;
  timeoutMs?: number;
  retries?: number;
}

const HOUR = 3_600_000;
export const TTL_MS = 24 * HOUR;
export const TTL_404_MS = HOUR;

const NPM_NAME = /^(?:@[a-z0-9][a-z0-9~._-]*\/)?[a-z0-9][a-z0-9~._-]*$/i;
const PYPI_NAME = /^[a-z0-9][a-z0-9._-]*$/i;

/** Names come from an untrusted repo: only well-formed names ever reach a URL or a file path. */
export function isValidName(eco: Ecosystem, name: string): boolean {
  return name.length <= 214 && (eco === "npm" ? NPM_NAME.test(name) : PYPI_NAME.test(name));
}

export function registryUrl(eco: Ecosystem, name: string): string {
  return eco === "npm"
    ? `https://registry.npmjs.org/${name.replace("/", "%2F")}`
    : `https://pypi.org/pypi/${encodeURIComponent(name)}/json`;
}

export function parseNpm(doc: unknown, now: number): RegistryRecord | undefined {
  if (typeof doc !== "object" || doc === null) return undefined;
  const d = doc as { time?: Record<string, unknown>; "dist-tags"?: { latest?: unknown } };
  if (typeof d.time !== "object" || d.time === null) return undefined;
  const times: Record<string, string> = {};
  for (const [k, v] of Object.entries(d.time)) if (k !== "created" && k !== "modified" && typeof v === "string") times[k] = v;
  const created = typeof d.time.created === "string" ? d.time.created : earliest(Object.values(times));
  const latest = d["dist-tags"]?.latest;
  return { status: 200, fetchedAt: now, created, latest: typeof latest === "string" ? latest : undefined, times };
}

export function parsePypi(doc: unknown, now: number): RegistryRecord | undefined {
  if (typeof doc !== "object" || doc === null) return undefined;
  const d = doc as { info?: { version?: unknown }; releases?: Record<string, unknown> };
  if (typeof d.releases !== "object" || d.releases === null) return undefined;
  const times: Record<string, string> = {};
  const sdistOnly: string[] = [];
  for (const [version, files] of Object.entries(d.releases)) {
    if (!Array.isArray(files) || files.length === 0) continue;
    const typed = files.filter((f): f is { packagetype?: string; upload_time_iso_8601?: string } => typeof f === "object" && f !== null);
    const t = earliest(typed.map((f) => f.upload_time_iso_8601).filter((x): x is string => typeof x === "string"));
    if (t) times[version] = t;
    if (typed.some((f) => f.packagetype === "sdist") && !typed.some((f) => f.packagetype === "bdist_wheel")) sdistOnly.push(version);
  }
  const latest = d.info?.version;
  return {
    status: 200,
    fetchedAt: now,
    created: earliest(Object.values(times)),
    latest: typeof latest === "string" ? latest : undefined,
    times,
    sdistOnly,
  };
}

function earliest(times: string[]): string | undefined {
  let best: string | undefined;
  for (const t of times) {
    const ms = Date.parse(t);
    if (!Number.isNaN(ms) && (best === undefined || ms < Date.parse(best))) best = t;
  }
  return best;
}

function validRecord(x: unknown): x is RegistryRecord {
  if (typeof x !== "object" || x === null) return false;
  const r = x as Record<string, unknown>;
  if ((r.status !== 200 && r.status !== 404) || typeof r.fetchedAt !== "number") return false;
  if (r.created !== undefined && (typeof r.created !== "string" || Number.isNaN(Date.parse(r.created)))) return false;
  if (r.latest !== undefined && typeof r.latest !== "string") return false;
  if (r.times !== undefined && (typeof r.times !== "object" || r.times === null)) return false;
  if (r.sdistOnly !== undefined && !Array.isArray(r.sdistOnly)) return false;
  return true;
}

export class Registry {
  private readonly fetchFn: FetchLike;
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly cacheDir?: string;
  /** Requests actually sent (cache hits excluded). */
  requests = 0;

  constructor(opts: RegistryOptions = {}) {
    this.fetchFn = opts.fetch ?? ((url, init) => fetch(url, init));
    this.now = opts.now ?? Date.now;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.retries = opts.retries ?? 2;
    this.cacheDir = opts.cacheDir;
  }

  private cachePath(eco: Ecosystem, name: string): string | undefined {
    if (!this.cacheDir) return undefined;
    return join(this.cacheDir, eco.toLowerCase(), `${name.replace("/", "__")}.json`);
  }

  private async readCache(eco: Ecosystem, name: string): Promise<RegistryRecord | undefined> {
    const path = this.cachePath(eco, name);
    if (!path) return undefined;
    try {
      const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
      return validRecord(parsed) ? parsed : undefined;
    } catch {
      return undefined;
    }
  }

  private async writeCache(eco: Ecosystem, name: string, record: RegistryRecord): Promise<void> {
    const path = this.cachePath(eco, name);
    if (!path) return;
    try {
      await mkdir(join(path, ".."), { recursive: true, mode: 0o700 });
      const tmp = `${path}.${process.pid}.tmp`;
      await writeFile(tmp, JSON.stringify(record), { mode: 0o600 });
      await rename(tmp, path);
    } catch {
      // The cache is an optimization only.
    }
  }

  async lookup(eco: Ecosystem, name: string): Promise<Lookup> {
    if (!isValidName(eco, name)) return { error: "invalid package name" };
    const cached = await this.readCache(eco, name);
    const age = cached ? this.now() - cached.fetchedAt : Infinity;
    if (cached && age >= 0 && age < (cached.status === 404 ? TTL_404_MS : TTL_MS)) return { record: cached };

    const got = await this.request(registryUrl(eco, name));
    if ("error" in got) return { error: got.error };
    const now = this.now();
    let record: RegistryRecord | undefined;
    if (got.status === 404) record = { status: 404, fetchedAt: now };
    else {
      record = eco === "npm" ? parseNpm(got.body, now) : parsePypi(got.body, now);
      if (!record) return { error: "unexpected registry response" };
      // The first-publish date is kept forever: it only ever moves earlier.
      if (cached?.created && (!record.created || Date.parse(cached.created) < Date.parse(record.created))) record.created = cached.created;
    }
    await this.writeCache(eco, name, record);
    return { record };
  }

  private async request(url: string): Promise<{ status: number; body?: unknown } | { error: string }> {
    let lastError = "request failed";
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      if (attempt > 0) await this.sleep(500 * 2 ** (attempt - 1));
      try {
        this.requests++;
        const res = await this.fetchFn(url, {
          headers: { "user-agent": `${TOOL_NAME}/${TOOL_VERSION}`, accept: "application/json" },
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        if (res.status === 404) return { status: 404 };
        if (res.status === 429 || res.status >= 500) {
          lastError = `HTTP ${res.status}`;
          continue;
        }
        if (!res.ok) return { error: `HTTP ${res.status}` };
        return { status: res.status, body: await res.json() };
      } catch (e) {
        lastError = e instanceof Error ? e.name : "request failed";
      }
    }
    return { error: lastError };
  }
}
