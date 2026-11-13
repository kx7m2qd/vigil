import type { EngineName } from "../core/finding.js";

/** Engines that run as a downloaded binary. `pkgrisk` is built in (no binary to resolve). */
export type BinaryEngine = Exclude<EngineName, "pkgrisk">;

export type Platform = "darwin-arm64" | "linux-x64";

export interface Artifact {
  url: string;
  sha256: string;
  /**
   * Present when the download is an archive; `member` is the file to extract and
   * `sha256` is the hash of that extracted binary (re-checked before every run).
   */
  archive?: { type: "tar.gz"; member: string; sha256: string };
}

export interface EngineSpec {
  version: string;
  binary: string;
  artifacts: Partial<Record<Platform, Artifact>>;
}

/**
 * Pinned engine binaries. Bumping a version means: download, verify against the
 * upstream checksum/signature, then update both the version and the sha256 here.
 *
 * osv-scanner and gitleaks hashes match their published checksum files.
 * Opengrep publishes Sigstore signatures (.sig/.cert) instead of checksums; its
 * hashes match the asset digests GitHub reports for the release (checked
 * 2026-10-22). TODO: also verify with `cosign verify-blob` before the first
 * public release (docs/SECURITY.md).
 */
export const ENGINES: Record<BinaryEngine, EngineSpec> = {
  opengrep: {
    version: "1.30.1",
    binary: "opengrep",
    artifacts: {
      "darwin-arm64": {
        url: "https://github.com/opengrep/opengrep/releases/download/v1.30.1/opengrep_osx_arm64",
        sha256: "7b788794e111ce3fb83f0aa52c100a3b85d37d8b59482262109031f50d4a8d91",
      },
      "linux-x64": {
        url: "https://github.com/opengrep/opengrep/releases/download/v1.30.1/opengrep_manylinux_x86",
        sha256: "d3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4",
      },
    },
  },
  "osv-scanner": {
    version: "2.6.0",
    binary: "osv-scanner",
    artifacts: {
      "darwin-arm64": {
        url: "https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_darwin_arm64",
        sha256: "98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4",
      },
      "linux-x64": {
        url: "https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_linux_amd64",
        sha256: "ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108",
      },
    },
  },
  gitleaks: {
    version: "8.30.1",
    binary: "gitleaks",
    artifacts: {
      "darwin-arm64": {
        url: "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz",
        sha256: "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
        archive: {
          type: "tar.gz",
          member: "gitleaks",
          sha256: "ba52fb1bfabbcde42f032afad3d6e0b19dff8ed105229a16e7caa338bbc0e84f",
        },
      },
      "linux-x64": {
        url: "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
        sha256: "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
        archive: {
          type: "tar.gz",
          member: "gitleaks",
          sha256: "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509",
        },
      },
    },
  },
};

export function currentPlatform(): Platform | undefined {
  const key = `${process.platform}-${process.arch}`;
  if (key === "darwin-arm64") return "darwin-arm64";
  if (key === "linux-x64") return "linux-x64";
  return undefined;
}

export const BINARY_ENGINES = Object.keys(ENGINES) as BinaryEngine[];
