# Vigil — Build Approach

> Working name. Rename freely; the name lives in `package.json`, `src/version.ts` and this doc.

## 1. What we are building

An application security scanner for developer teams that **finds fewer, realer issues, proves
which ones matter, and fixes them** — built for codebases that AI writes.

We are not trying to out-build Sparrow's 15-year-old engines. We wrap proven open-source engines
and own the layer above them, which is where Sparrow is weakest:

| Sparrow's weakness (from research)          | Our answer                                              |
|---------------------------------------------|---------------------------------------------------------|
| Vague fix advice, thin finding descriptions | AI triage with written reasoning per finding            |
| Low recall (49 missed vs 14 found in ACM study) | Public benchmark gate on every change                |
| Upload-your-code workflow                   | Scans run locally / in the customer's CI; only findings leave |
| Features split by tier/module, per-user price | One product, every engine, every tier                 |
| Rationed AI fixes (200/month)               | Verified fix PRs, no quota                               |
| Few integrations, no public docs            | GitHub-native, SARIF, CLI, MCP, public docs              |

## 2. Principles (non-negotiable)

1. **Local-first.** Engines run on the developer's machine or their CI. Source code never
   reaches our servers. This removes breach liability and compute cost for a solo builder.
2. **Measured, not claimed.** Every rule and every triage prompt is scored by the benchmark
   (`npm run bench`). A change that lowers precision or recall below the gate does not merge.
3. **Every rule ships with tests.** A rule without `ruleid:` and `ok:` test cases is not a rule.
4. **Pinned, verified engines.** Engine binaries are pinned by version and SHA-256.
5. **Never leak secrets.** Secret values are redacted at the normalizer; raw values never reach
   output, logs, or the AI layer.
6. **One finding model.** All engines normalize into `Finding` (`src/core/finding.ts`).
   Everything downstream (reports, triage, dashboard, PR comments) only sees `Finding`.

## 3. Architecture

```
 vigil scan <path>
      │
      ├─ engines/opengrep   → our rules in rules/   ─┐
      ├─ engines/osv        → lockfiles (SCA)        ├─ normalize → Finding[] → ignore → dedupe
      └─ engines/gitleaks   → secrets               ─┘                  │
                                                                         ├─ report: text / json / sarif
                                                         (Phase 1 →)     ├─ AI triage  (Claude API)
                                                                         ├─ fix + verify → PR
                                                                         └─ upload findings → dashboard
```

Code layout:

```
src/core/       Finding model, fingerprints, severity, ignore rules
src/engines/    one file per engine: run it, normalize its JSON; manifest.ts pins binaries
src/report/     text, sarif
src/cli.ts      entry point
rules/          our own Opengrep rules, each with a same-named test file
bench/          labeled benchmark cases + scorer
test/           unit tests (vitest)
```

## 4. Roadmap (solo engineer + Claude Code)

### Phase 0 — Foundation (weeks 0–4)  ✓ done
- [x] CLI: `vigil scan` with text/json/sarif output and `--fail-on`
- [x] Engines: Opengrep, osv-scanner, Gitleaks — pinned, checksum-verified, auto-installed
- [x] Unified `Finding` model with stable fingerprints
- [x] First 10 rules (JS/TS + Python) with tests
- [x] Benchmark harness with precision/recall gate (`bench/run.ts`, `bench/thresholds.json`, first cases)
- [x] Unit tests for the Finding model, ignore rules, engine normalizers, SARIF
- [x] Grow rules to ~40 using the rule loop (§5) — 40 rules (JS + Python); every OWASP Python category has a rule
- [x] OWASP Benchmark for Python: `npm run bench:owasp`, pinned + checksum-verified, per-category gate
  (no labelled OWASP suite exists for JS)
- [x] 20 real CVE fixes (npm + PyPI advisories): `npm run bench:cves`, vulnerable vs fixed file, pinned + verified

### Phase 1 — MVP (months 1–3)  ← we are here
- AI triage: per new finding, build context (code slice + taint trace) → Claude → verdict
  (`true_positive | false_positive | needs_review`) + explanation. Cache by fingerprint.
- Fix agent: patch → re-scan → run project tests → only then propose.
- Malicious / non-existent package detection for npm + PyPI (typosquats, install scripts,
  brand-new packages, packages AI tools hallucinate).
- Basic reachability for JS/Python: is the vulnerable function imported/called?
- GitHub App + Action: PR comments on changed lines, check run, fix PRs.
- MCP server exposing `scan`, `explain`, `fix` to Claude Code / Cursor.
- Pre-commit hook (`vigil hook install`): secrets + changed-file scan, fast enough to never be skipped.
- Triage memory: "false positive" / "won't fix" decisions are stored per org and fed back into
  triage, so each repo gets quieter over time (instead of hand-kept exclude lists).
- Ownership: route each finding to an owner via CODEOWNERS, falling back to git blame.
- AI-app rules: LLM output → SQL/shell/eval sinks, prompt-injection paths, unsafe model loading
  (pickle / `torch.load`), over-permissioned MCP server configs. (Started: `py-llm-output-to-dangerous-sink`.)
- Dashboard: Next.js + Supabase, findings list, Stripe billing. Receives findings only.

### Phase 2 — Platform (months 4–8, once users arrive)
- Access-control pentest agent (multi-role IDOR testing): the headline feature.
- VS Code, then JetBrains extension; GitLab.
- Java + Go, IaC (Checkov), SBOM/VEX + AI-BOM (models, prompts, AI SDKs) + Cosign signing.
- Runtime context (read-only cloud / Kubernetes): rank findings that are reachable in code,
  deployed, and internet-exposed above everything else.
- Fix SLAs by severity; time-to-fix and fix-rate dashboards for security leads.

### Later (pull in only on customer demand)
Mobile (APK/IPA), API discovery + OpenAPI diff, threat-model-from-code agent, importers for
Sparrow / Snyk / SonarQube results, SOC 2 / ISO 27001 / EU CRA evidence export.

### Not before year 2
Full DAST crawler, RASP, C/C++/MISRA, air-gapped deployments, Common Criteria.

## 5. How we work (the loops)

### Feature loop
1. Write a short spec in `docs/specs/<feature>.md`: goal, inputs/outputs, edge cases, done-criteria.
2. Ask Claude Code to implement it **with tests**, referencing the spec.
3. `npm run check` (typecheck + unit tests + rule tests) and `npm run bench`.
4. Review the diff yourself — always by hand for anything touching auth, tokens, GitHub
   permissions, network calls, or secret handling.

### Rule loop (aim: 10–20 rules/week)
1. Pick a vulnerability class or a real CVE + its fix commit.
2. Prompt: *"Write an Opengrep rule `<id>` for <class>. Add `rules/<lang>/<id>.<ext>` with at
   least 3 `ruleid:` cases and 3 `ok:` cases including the realistic safe fix. Run
   `npm run test:rules` and `npm run bench`."*
3. Add a realistic bench case if the class isn't covered yet.
4. Merge only if rule tests pass and the bench gate holds.

### Definition of done
- Typecheck, unit tests, rule tests pass (`npm run check`).
- Bench gate passes and `bench/results/latest.json` is committed with the change.
- Docs updated if behavior or CLI changed.

## 6. Cost control for the AI layer (Phase 1)
Claude Pro/Max pays for *building*; the product's AI calls use the Claude API (billed per token).
- Triage only new fingerprints; cache verdicts forever per fingerprint + rule version.
- Default triage on a small model; escalate to a larger model only for `needs_review` and fixes.
- Send minimal context (taint path slice, not whole files).
- Offer bring-your-own-API-key for teams.

## 7. Risks we watch
- **Accuracy drift** from AI-written rules → bench gate.
- **Our own security** → no stored source code, minimal GitHub App permissions, secret redaction.
  Anything that ever runs server-side (pentest agent, hosted fix runs): a fresh sandbox per job,
  per-customer encryption keys, no training on customer data, written retention policy.
- **Scope creep** → this roadmap; anything not in the current phase waits.
- **Licensing** → we do not ship Semgrep's official rule registry (its license forbids competing
  SaaS use). All rules in `rules/` are written by us. Get a legal check before launch.
