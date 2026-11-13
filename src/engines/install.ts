import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { chmod, mkdir, mkdtemp, rename, rm, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { ENGINES, currentPlatform, type Artifact, type BinaryEngine as EngineName } from "./manifest.js";
import { run } from "./run.js";

export function cacheRoot(): string {
  if (process.env.VIGIL_HOME) return process.env.VIGIL_HOME;
  const xdg = process.env.XDG_CACHE_HOME ?? join(homedir(), ".cache");
  return join(xdg, "vigil");
}

export function enginePath(name: EngineName): string {
  const spec = ENGINES[name];
  return join(cacheRoot(), "engines", name, spec.version, spec.binary);
}

export function overrideVar(name: EngineName): string {
  return `VIGIL_${name.replace(/-/g, "_").toUpperCase()}_BIN`;
}

function pinnedArtifact(name: EngineName): Artifact | undefined {
  const platform = currentPlatform();
  return platform ? ENGINES[name].artifacts[platform] : undefined;
}

/** The hash the installed binary itself must have. */
function binarySha256(artifact: Artifact): string {
  return artifact.archive?.sha256 ?? artifact.sha256;
}

async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}

async function isFile(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

/**
 * True only if the cached binary exists and still matches its pinned hash. Checked
 * on every run, so a tampered or poisoned cache (e.g. a restored CI cache) is never
 * executed.
 */
export async function isInstalled(name: EngineName): Promise<boolean> {
  const artifact = pinnedArtifact(name);
  const path = enginePath(name);
  if (!artifact || !(await isFile(path))) return false;
  return (await sha256File(path)) === binarySha256(artifact);
}

/**
 * Download the pinned artifact, verify its SHA-256, and place the binary in the
 * cache. A checksum mismatch aborts without writing anything executable.
 */
export async function installEngine(name: EngineName): Promise<string> {
  const spec = ENGINES[name];
  const artifact = pinnedArtifact(name);
  if (!artifact) {
    throw new Error(
      `No pinned ${name} build for ${process.platform}-${process.arch}. ` +
        `Install ${name} ${spec.version} yourself and set ${overrideVar(name)}.`,
    );
  }

  const res = await fetch(artifact.url);
  if (!res.ok) throw new Error(`Downloading ${name}: HTTP ${res.status} from ${artifact.url}`);
  const bytes = Buffer.from(await res.arrayBuffer());
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== artifact.sha256) {
    throw new Error(`Checksum mismatch for ${name}: expected ${artifact.sha256}, got ${actual}. Refusing to install.`);
  }

  const target = enginePath(name);
  const targetDir = join(target, "..");
  await mkdir(targetDir, { recursive: true, mode: 0o700 });
  // Stage next to the target so the final rename is atomic (and never crosses filesystems).
  const work = await mkdtemp(join(targetDir, ".staging-"));
  try {
    let staged: string;
    if (artifact.archive) {
      const archivePath = join(work, "artifact.tar.gz");
      await writeFile(archivePath, bytes, { mode: 0o600 });
      const { code, stderr } = await run("tar", ["-xzf", archivePath, "-C", work, "--", artifact.archive.member]);
      if (code !== 0) throw new Error(`Extracting ${name}: ${stderr}`);
      staged = join(work, artifact.archive.member);
    } else {
      staged = join(work, spec.binary);
      await writeFile(staged, bytes, { mode: 0o600 });
    }
    const binHash = await sha256File(staged);
    if (binHash !== binarySha256(artifact)) {
      throw new Error(`Checksum mismatch for extracted ${name} binary: got ${binHash}. Refusing to install.`);
    }
    await chmod(staged, 0o755);
    await rename(staged, target);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
  return target;
}

/**
 * Resolve an engine binary: env override, then the verified cache, then
 * (optionally) a fresh verified install. A cached binary that fails verification
 * is replaced, never run.
 */
export async function resolveEngine(name: EngineName, opts: { autoInstall: boolean }): Promise<string> {
  const override = process.env[overrideVar(name)];
  if (override) return override;
  if (await isInstalled(name)) return enginePath(name);
  if (!opts.autoInstall) {
    const present = await isFile(enginePath(name));
    throw new Error(
      present
        ? `${name} in the cache does not match its pinned checksum. Run \`vigil engines install\` to replace it.`
        : `${name} is not installed. Run \`vigil engines install\`.`,
    );
  }
  return installEngine(name);
}
