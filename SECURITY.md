# Security policy

## Reporting a vulnerability

Please **don't open a public issue** for a security problem in Vigil.

Report it privately through GitHub: **Security → Report a vulnerability** on
<https://github.com/kx7m2qd/vigil/security/advisories/new>.

Include what you found, how to reproduce it, and the impact you expect. You'll get an
acknowledgement within 3 working days and a fix or a plan within 30 days. We'll credit you in the
advisory unless you'd rather stay anonymous.

## Supported versions

Only the latest release and `main` get security fixes while Vigil is pre-1.0.

## What's in scope

Vigil reads untrusted repositories, so these are the things we treat as vulnerabilities:

- Running code from a scanned repo, or letting it change what Vigil executes
- A raw secret value appearing in a finding, report, log, or anything sent off the machine
- Source code leaving the machine (only package names/versions go to registries and osv.dev;
  `--offline` sends nothing)
- Installing or running an engine binary that doesn't match its pinned SHA-256
- A scanned repo hiding findings from CI in a way the report doesn't surface
- Terminal escape or injection through finding text, or injection through GitHub Action inputs

Missed detections and false positives are bugs, not vulnerabilities. Open a normal issue for those.
