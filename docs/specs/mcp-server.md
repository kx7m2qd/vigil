# MCP server (`vigil mcp`)

Lets coding agents (Claude Code, Cursor, …) run Vigil on the code they just wrote, and check a
package before installing it.

```
claude mcp add vigil -- npx -y @kx7m2qd/vigil mcp
```
Cursor (`.cursor/mcp.json`): `{"mcpServers": {"vigil": {"command": "npx", "args": ["-y", "@kx7m2qd/vigil", "mcp"]}}}`

Releases: push a `vX.Y.Z` tag matching `package.json` and `src/version.ts`; `.github/workflows/release.yml`
runs the gates and publishes to npm with provenance (repo secret `NPM_TOKEN`).

## Decisions (2026-11-14)
- **Tools:** `scan`, `explain`, `check_package`. `fix` comes with the fix agent.
- **No SDK.** Hand-written JSON-RPC 2.0 over stdio, newline-delimited, Node built-ins only
  (`src/mcp/`). Vigil is a supply-chain tool; it keeps zero runtime dependencies. Handles
  `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`. Moving to the
  SDK is on the table only if we need resources, prompts or sampling.
- **Only `Finding` data reaches the model.** No code snippets (the agent can read files itself),
  no dataflow snippets, secrets are redacted by the engines already. stdout carries protocol only;
  logs go to stderr.
- **Default scope is changed files** (working tree vs `HEAD`, plus untracked files). `scope: "all"`
  scans the whole root; `paths` scans named files. Changed/paths scans copy those files into a
  private temp dir and run Opengrep + Gitleaks there; if a dependency manifest or lockfile changed,
  osv-scanner + pkgrisk also run on the real root.
- **Output is capped.** `scan` returns a compact list (default 50, max 200) sorted by severity,
  with totals per severity and a hint when truncated. `explain <id>` returns the full detail of one
  finding from the last scan (message, CWE/OWASP, dataflow path/lines, reachability evidence, fixed
  versions).
- **The server is confined to its root** (`vigil mcp [path]`, default cwd). Paths outside it are
  rejected.
- **Distribution:** npm as `@kx7m2qd/vigil`, published from CI with provenance.

## Tools

### `scan`
Input: `{ scope?: "changed" | "all", paths?: string[], engines?: string[], offline?: boolean, limit?: number }`
Output (JSON text): `{ root, scope, files?, totals, shown, findings: [{ id, severity, confidence?,
rule, title, location, reachability? }], warnings, hint? }`

### `explain`
Input: `{ id }` — an id from the last `scan` in this session.
Output: the finding without snippets, plus CWE links.

### `check_package`
Input: `{ ecosystem: "npm" | "PyPI", name, version? }`
Output: `{ verdict: "ok" | "caution" | "block" | "unverified", findings, notes }`.
`block` for non-existent packages and likely typosquats, `caution` for brand-new packages or
versions, `unverified` when the registry could not be reached. Uses the pkgrisk rules
(see `package-risk.md`); install-script data needs a lockfile, so it is not checked here.

## Not in scope
- `fix` (needs the fix agent), resources/prompts, HTTP transport.
