# Action: PR comments + check run

Goal: on a pull request, a reviewer sees Vigil's findings where they read code: inline comments on
the lines the PR adds, and a "Vigil" check run with annotations. Push events get the check run only.

## Inputs (action.yml)
- `pr-comments` (default `true`): review comments on added lines.
- `check-run` (default `true`): a completed `Vigil` check run on the PR head (or pushed) commit.
- `comment-min-severity` (default `medium`): weaker findings go to the check run only.
- `github-token` (default `${{ github.token }}`).

Permissions: `checks: write` for the check run, `pull-requests: write` for comments. Missing
permission (or a fork PR's read-only token) → one `::notice::` naming what to grant, never a failure.
The severity gate stays in the Gate step; this step never changes the job result.

## Behaviour
- Input is the SARIF the Scan step wrote (only `Finding` data; no source is read or sent).
  Paths are made repo-relative with the scan path's git prefix.
- **Comments:** only findings whose start line is a `+` line in the PR diff (`GET pulls/{n}/files`
  patches). Each body carries a hidden `<!-- vigil:<fingerprint> -->`; findings already commented in
  this PR are skipped, so re-runs don't repeat. At most 25 new comments per run, most severe first,
  posted as one review (`event: COMMENT`). Files without a patch (too large/binary) are skipped.
- **Check run:** conclusion `success` (exit 0), `failure` (exit 1), `failure` titled "Scan error"
  (other). Annotations for every finding (cap 500, batches of 50): critical/high → `failure`,
  medium → `warning`, low/info → `notice`.
- **Untrusted text:** messages quote repo content. Escape HTML, neutralise `@mentions` and
  `#refs`, strip backticks, cap length.

## Done when
- Unit tests cover patch parsing, selection/dedupe/cap, body escaping, check run batching,
  permission errors (fake fetch, no network).
- `npm run check` + `npm run bench` pass; the self-scan workflow grants the permissions.
