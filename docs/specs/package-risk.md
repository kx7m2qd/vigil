# Spec: malicious / non-existent package detection (`pkgrisk` engine)

## Goal
Catch risky **dependencies** before they're installed or merged. osv-scanner only knows about
vulnerabilities and packages already reported as malicious. This catches the ones that haven't
been reported yet:
- **packages that don't exist.** AI tools often invent package names. Attackers register those
  names ("slopsquatting"), so a missing name is a hole waiting to be filled.
- **typosquats** of popular packages (`crossenv` → `cross-env`, `reqeusts` → `requests`).
- **brand-new** packages or versions (most malware is caught and removed within days).
- **install-time code** (npm `preinstall`/`install`/`postinstall`, PyPI sdist-only releases).
- **known-malicious** packages (OpenSSF `MAL-*` advisories that osv-scanner already returns).

npm and PyPI only.

## Where it lives
- A new engine `pkgrisk` written in TypeScript (no binary), in `src/engines/pkgrisk/`.
  `EngineName` gains `"pkgrisk"`, and `ALL_ENGINES` includes it.
- Output is normalized `Finding`s: `category: "dependency"`, `engine: "pkgrisk"`, `ruleId` from the
  table below, `dependency: { name, version, ecosystem, advisories: [], fixedVersions: [] }`,
  `location` = the manifest file + the line that declares the package (line 1 if it can't be found).
- Fingerprint: `fingerprint("pkgrisk", ruleId, ecosystem, name)`. The version is **left out**
  for every rule except `pkg-new-version`, so a finding stays the same across version bumps.

## Inputs (v1)
| Ecosystem | Files | Direct deps from | Resolved versions / install scripts from |
|---|---|---|---|
| npm | `package.json`, `package-lock.json` (v2/v3) | `dependencies`, `devDependencies`, `optionalDependencies` | lockfile `packages[*].version`, `hasInstallScript` |
| PyPI | `requirements*.txt`, `pyproject.toml` (`[project] dependencies`) | each requirement line | `==` pins only, otherwise the latest release |

- Every manifest found under the scan root, honouring `.vigilignore` and `DEFAULT_IGNORES`.
- Not in v1: yarn.lock, pnpm-lock.yaml, poetry.lock, Pipfile, uv.lock. They're noted in the report
  as "not checked by pkgrisk".
- `pyproject.toml` is read with a small parser that handles only the `dependencies = [ ... ]` array
  under `[project]`. No TOML dependency is added.
- Name normalization: PyPI per PEP 503 (lowercase, runs of `-_.` → `-`). npm names are taken
  as-is.
- Skipped: `file:`, `link:`, `git+…`, `http(s):`, `workspace:`, and local paths. They aren't
  registry packages.
- Private scopes and indexes: a package with an npm scope listed in `.npmrc` `@scope:registry=`, or
  any PyPI requirement when `--index-url`/`--extra-index-url` appears in the requirements file, is
  **not** checked against the public registry. A private package missing from public npm is not a
  finding (it would be a guaranteed false positive). It *is* recorded as a warning when the name
  also exists publicly, because that is the dependency-confusion setup.

## Rules
| ruleId | Signal | Severity | Confidence | Needs network |
|---|---|---|---|---|
| `pkg-known-malicious` | an osv-scanner advisory whose id starts with `MAL-` (rewrites osv's finding: severity critical, ruleId changed) | critical | high | via osv |
| `pkg-nonexistent` | the registry returns 404 for a **direct** dependency | critical | high | yes |
| `pkg-typosquat` | Damerau-Levenshtein distance ≤ 1 (≤ 2 for names ≥ 10 chars), or a separator/scope confusion (`cross-env`/`crossenv`, `@types/x` vs `types-x`), with a name in the popular list, while the package itself is **not** in the popular list | high | medium | no |
| `pkg-new-package` | the package was first published < 30 days ago | high | medium | yes |
| `pkg-new-version` | the resolved version was published < 72 h ago | medium | low | yes |
| `pkg-install-script` | npm: `hasInstallScript: true` in the lockfile. Reported **only together with** one of the signals above, or for direct deps outside the popular list. Otherwise it is just a count line ("12 dependencies run install scripts"), because esbuild, sharp and others legitimately use them | medium | low | no |
| `pkg-sdist-only` | PyPI: the resolved release has no wheel, so `setup.py` runs at install. Same reporting rule as `pkg-install-script` | medium | low | yes |

Each `message` says what was found, why it matters, and what to do ("check the spelling: did you
mean `cross-env`?", "pin to a version older than 72 h", "verify the publisher before installing").

## Popular-name lists (typosquat targets)
- `data/popular-npm.txt` and `data/popular-pypi.txt`: top ~5,000 names each, one per line (a JSON array trips gitleaks' generic-api-key rule).
- Sources: PyPI uses hugovk/top-pypi-packages (30-day downloads). npm uses the `npm-high-impact`
  package's list. Fetched by `npm run data:popular`, which pins the source URL and version and
  records the SHA-256 in `data/SOURCES.json`, the same discipline as `src/engines/manifest.ts`.
  The lists are committed and refreshed by hand. No fetch at scan time.

## Network
- What leaves the machine: **package names and versions only**, sent to `registry.npmjs.org` and
  `pypi.org/pypi/<name>/json`. osv-scanner already sends the same data to osv.dev. Source code,
  file paths and manifest contents are never sent. The README and help text say so.
- `--offline` (on `vigil scan`) turns off every network rule. Typosquat, install-script and MAL
  checks still run.
- Concurrency 8, 10 s timeout per request, 2 retries with backoff on 429/5xx. A User-Agent of
  `vigil/<version>` with no personal data.
- **Cache**: `.vigil-cache/pkgrisk/<ecosystem>/<name>.json` holding only the fields used (time map,
  dist-tags, version → hasInstallScript, wheel presence). TTL 24 h, and the first-publish date is
  kept forever. 404s are cached for 1 h only, so a package published later is picked up.
- Registry unreachable: a warning (`pkgrisk: registry unreachable, N packages not checked`), not an
  engine failure. The offline rules still produce results. Exit codes are unchanged.
- The pre-commit hook does **not** run pkgrisk (no network during a commit). A later version may
  run offline-only checks when a manifest is staged.

## Code layout
- `src/engines/pkgrisk/manifests.ts`: discover and parse files into
  `{ ecosystem, name, version?, direct, file, line, installScript? }[]` (pure parsers + discovery).
- `src/engines/pkgrisk/typosquat.ts`: normalization, distance, matching against the popular list
  (pure).
- `src/engines/pkgrisk/registry.ts`: fetch + cache via an injectable `fetch`, so tests never touch
  the network.
- `src/engines/pkgrisk/index.ts`: `runPkgrisk(root, ignores, { offline, fetch, now })` →
  `EngineOutput`.
- `src/engines/osv.ts`: `MAL-` advisories → `pkg-known-malicious`.
- `src/scan.ts` / `src/cli.ts`: wire the engine in and add `--offline`.

## Tests
- Parsers: package.json (all dep sections, line numbers), lockfile v3 (nested `node_modules/a/node_modules/b`,
  `hasInstallScript`), requirements (comments, `-r`, extras `pkg[extra]`, markers `; python_version<"3.9"`,
  `--index-url`, `-e`, URLs), pyproject `dependencies` array (multi-line, quotes).
- Typosquat: `crossenv`→`cross-env`, `reqeusts`→`requests`, `python-dateutil` vs `python3-dateutil`,
  `jeIlyfish` (capital I) vs `jellyfish`; no match for popular packages themselves, for short names
  (≤ 4 chars) at distance 1 (`ms`/`mz` style noise), or for known legit pairs listed in
  `data/typosquat-allow.json` (seeded with any FPs found on the corpus below).
- Registry with a fake fetch: 404 → nonexistent; created 5 days ago → new-package; a version 10 h old →
  new-version; 429 then 200 → retried; cache hit makes no request; offline → no fetch calls.
- Private scope in `.npmrc` → not checked publicly.
- osv `MAL-` → critical `pkg-known-malicious`.
- Bench: `bench/cases/supply-chain/` with an npm project and a Python project, each containing a
  typosquat, a non-existent name, and normal deps. Its registry responses are recorded fixtures
  (`bench` runs offline with an injected fetch), so the bench gate stays deterministic.

## False-positive check before merge
Run `vigil scan --engines pkgrisk` on the lockfiles of this repo, Juice Shop, NodeGoat and 3 popular
Python projects (Django, Flask, requests). The target is **zero** `pkg-typosquat` / `pkg-nonexistent`
findings. Any hit gets fixed in the matcher or added to the allow-list, with the reason recorded.

## Done
- `npm run check` and `npm run bench` pass. The help text documents `--offline` and what is sent
  over the network.
- The FP-check results are recorded in the commit message.
