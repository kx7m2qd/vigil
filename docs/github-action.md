# Vigil GitHub Action

Runs Vigil on every push and pull request, inside your own GitHub runner. Source code never leaves
the runner; only the SARIF report is uploaded, to your repo's own code scanning.

```yaml
# .github/workflows/vigil.yml
name: Vigil
on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # for the code scanning upload
    steps:
      - uses: actions/checkout@v7
      - uses: kx7m2qd/vigil@main
        with:
          fail-on: high
```

Results appear in three places: a red/green check on the PR, alerts in **Security → Code
scanning** (annotated on changed lines in the PR), and a findings table in the run's job summary.

## Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Directory to scan |
| `fail-on` | `high` | Fail if any finding is at least this severe (`critical`…`info`, or `none`) |
| `trust-reachability` | `false` | Let `fail-on` use the lowered severity of dependencies nothing uses |
| `reachable-only` | `false` | Leave unreachable dependency findings out entirely |
| `offline` | `false` | Skip npm/PyPI registry lookups (package names only are ever sent) |
| `engines` | all | Comma-separated subset: `opengrep,osv-scanner,gitleaks,pkgrisk` |
| `upload-sarif` | `true` | Upload to code scanning. Private repos need GitHub Advanced Security. |
| `sarif-file` | `vigil.sarif` | Where the report is written (also an output, for later steps) |

Outputs: `exit-code` (0 clean, 1 findings at/above `fail-on`, 2 scan error) and `sarif-file`.

## Notes
- Linux x64 runners only for now (the pinned engine binaries are linux-x64 and darwin-arm64).
- Engine binaries are cached between runs and re-checked against their pinned SHA-256 every run.
- Paths in `.vigilignore` at the scan root are skipped.
- Pin to a commit SHA instead of `@main` if you want the action itself to stay fixed.
