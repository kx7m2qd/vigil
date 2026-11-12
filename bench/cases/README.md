# Benchmark cases

Small, realistic apps that are **intentionally vulnerable**. Excluded from `vigil scan` via `.vigilignore`.

Label every real vulnerability with a comment on the line directly above it:

    // expect: js-sql-injection        (JS/TS)
    # expect: py-command-injection     (Python)

Everything not labeled is expected to be clean. `npm run bench` scores:

- a finding on a labeled line with the same rule id → true positive
- otherwise, a finding on a labeled line from another rule for the same CWE → true positive, listed
  under "by sibling" (the labeled rule itself still missed that shape)
- a finding anywhere else → false positive
- a label with no matching finding → false negative (missed)

Write cases the way real code looks, not the way our rules look. Cases our rules miss are the point:
they show where recall is lost. Include the realistic safe fix next to each bug.

## OWASP Benchmark for Python (`npm run bench:owasp`)

`bench/owasp.ts` downloads [OWASP BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython)
at a pinned commit, checks its SHA-256 and caches it under the Vigil cache directory. It is GPL-3.0,
so it is never copied into this repo. Each test file is scored per category the OWASP way:
**score = true-positive rate − false-positive rate** (0 = no better than guessing).

Results go to `bench/results/owasp-python.json`. `bench/owasp-thresholds.json` holds a minimum score
per category; raise a category's number when a rule improves it, and add a category once we have a
rule for it. There is no equivalent labelled suite for JavaScript, so JS is covered by the cases
in this folder and by real CVE fixes.

## Real CVE fixes (`npm run bench:cves`)

`bench/cves.json` lists 20 published GitHub advisories (npm and PyPI) whose fix is a single commit.
For each one it pins the vulnerable file (the fix commit's parent), the fixed file, their SHA-256s,
and the line the fix changed. `bench/cves.ts` downloads both files from the upstream repo, verifies
them, scans them, and checks the case's rule fires on the vulnerable line and **not** on the fixed one.
The files keep their projects' licenses, so they are cached under the Vigil cache directory, never
copied here. `bench/cve-thresholds.json` gates detection recall and the number of fixes still flagged.

To add a case, pick an advisory with exactly one fix commit, record the sink line before and the
replacement line after, and pin both files' hashes. Prefer cases our rules miss: that is the point.
