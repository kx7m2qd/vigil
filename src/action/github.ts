// PR review comments + check run for the GitHub Action, built from Vigil's SARIF report.
// Spec: docs/specs/pr-feedback.md. Only Finding data (via SARIF) is sent; no source is read.
import { SEVERITY_ORDER, severityAtLeast, type Severity } from "../core/finding.js";
import { TOOL_NAME } from "../version.js";

export interface ReportItem {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  message: string;
  /** Repo-relative, forward slashes. */
  path: string;
  line: number;
  endLine?: number;
  reachability?: string;
}

export const MAX_COMMENTS = 25;
export const MAX_ANNOTATIONS = 500;
const ANNOTATION_BATCH = 50;
const MARKER = /<!-- vigil:([A-Za-z0-9_.:]+) -->/;
/** Fingerprint as it appears in a comment marker (no "-" so it can never close the comment). */
const markerId = (id: string) => id.replace(/[^A-Za-z0-9_.:]/g, "");

const SCORE_TO_SEVERITY: [number, Severity][] = [
  [9, "critical"],
  [7, "high"],
  [4, "medium"],
  [0.1, "low"],
  [0, "info"],
];

/** Reads the SARIF the Scan step wrote. `prefix` is the scan path relative to the repo root ("" or "pkg/"). */
export function itemsFromSarif(sarif: unknown, prefix = ""): ReportItem[] {
  const run = (sarif as { runs?: any[] })?.runs?.[0] ?? {};
  const rules: any[] = run.tool?.driver?.rules ?? [];
  const out: ReportItem[] = [];
  for (const r of run.results ?? []) {
    const rule = rules[r.ruleIndex] ?? {};
    const loc = r.locations?.[0]?.physicalLocation;
    const uri: string | undefined = loc?.artifactLocation?.uri;
    const line = Number(loc?.region?.startLine);
    if (!uri || !Number.isInteger(line) || line < 1) continue;
    const score = Number(rule.properties?.["security-severity"] ?? 0);
    out.push({
      id: String(r.partialFingerprints?.[`${TOOL_NAME}/v1`] ?? `${r.ruleId}:${uri}:${line}`),
      ruleId: String(rule.name ?? r.ruleId ?? ""),
      title: String(rule.shortDescription?.text ?? rule.name ?? ""),
      severity: SEVERITY_ORDER.includes(r.properties?.severity) ? r.properties.severity : SCORE_TO_SEVERITY.find(([min]) => score >= min)![1],
      message: String(r.message?.text ?? ""),
      path: joinPath(prefix, uri),
      line,
      ...(Number.isInteger(loc?.region?.endLine) ? { endLine: loc.region.endLine } : {}),
      ...(r.properties?.reachability ? { reachability: String(r.properties.reachability) } : {}),
    });
  }
  return out.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}

function joinPath(prefix: string, uri: string): string {
  const p = prefix.replace(/\\/g, "/").replace(/^\.?\/+/, "").replace(/\/*$/, "");
  const u = uri.replace(/\\/g, "/").replace(/^\.\//, "");
  return p ? `${p}/${u}` : u;
}

/** Line numbers (new side) that a unified-diff patch adds. */
export function addedLines(patch: string): Set<number> {
  const added = new Set<number>();
  let line = 0;
  for (const l of patch.split("\n")) {
    const h = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(l);
    if (h) {
      line = Number(h[1]);
      continue;
    }
    if (line === 0) continue;
    if (l.startsWith("+")) added.add(line++);
    else if (l.startsWith("-") || l.startsWith("\\")) continue;
    else line++;
  }
  return added;
}

/** Finding text quotes repo content: keep it from rendering HTML, pinging people or linking issues. */
export function safeText(s: string, max = 1000): string {
  const t = s
    .replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" })[c]!)
    .replace(/`/g, "'")
    .replace(/@(?=[A-Za-z0-9])/g, "@​")
    .replace(/#(?=\d)/g, "#​");
  return t.length > max ? `${t.slice(0, max)}…` : t;
}

export function commentBody(f: ReportItem): string {
  const lines = [
    `**${TOOL_NAME} · ${f.severity}** · ${safeText(f.title, 200)} (\`${safeText(f.ruleId, 120)}\`)`,
    "",
    safeText(f.message),
  ];
  if (f.reachability) lines.push("", `Reachability: ${safeText(f.reachability, 40)}`);
  lines.push("", `<!-- vigil:${markerId(f.id)} -->`);
  return lines.join("\n");
}

/** Findings to comment on: on an added line, at least `minSeverity`, not yet commented, capped. */
export function selectComments(
  items: ReportItem[],
  added: Map<string, Set<number>>,
  alreadyCommented: Set<string>,
  minSeverity: Severity,
): { comments: ReportItem[]; skipped: number } {
  const eligible = items.filter(
    (f) =>
      severityAtLeast(f.severity, minSeverity) &&
      added.get(f.path)?.has(f.line) === true &&
      !alreadyCommented.has(markerId(f.id)),
  );
  return { comments: eligible.slice(0, MAX_COMMENTS), skipped: Math.max(0, eligible.length - MAX_COMMENTS) };
}

const ANNOTATION_LEVEL: Record<Severity, "failure" | "warning" | "notice"> = {
  critical: "failure",
  high: "failure",
  medium: "warning",
  low: "notice",
  info: "notice",
};

export function annotations(items: ReportItem[]): object[] {
  return items.slice(0, MAX_ANNOTATIONS).map((f) => ({
    path: f.path,
    start_line: f.line,
    end_line: f.endLine && f.endLine >= f.line ? f.endLine : f.line,
    annotation_level: ANNOTATION_LEVEL[f.severity],
    title: `${f.severity}: ${f.title}`.slice(0, 255),
    message: f.message.slice(0, 4000) || f.title,
  }));
}

export function checkOutput(items: ReportItem[], exitCode: number): { conclusion: string; title: string; summary: string } {
  const counts = SEVERITY_ORDER.map((s) => `${items.filter((f) => f.severity === s).length} ${s}`).join(", ");
  if (exitCode === 0) return { conclusion: "success", title: `${items.length} finding${items.length === 1 ? "" : "s"}, none at or above fail-on`, summary: counts };
  if (exitCode === 1) return { conclusion: "failure", title: "Findings at or above fail-on", summary: counts };
  return { conclusion: "failure", title: "Scan error", summary: `Vigil could not complete the scan (exit ${exitCode}). See the Scan step log.` };
}

// ---- GitHub API -------------------------------------------------------------------------------

export class GitHubError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export interface Ctx {
  api: string;
  repo: string;
  token: string;
  fetch: typeof fetch;
}

async function gh(ctx: Ctx, method: string, path: string, body?: unknown): Promise<any> {
  const res = await ctx.fetch(`${ctx.api}/repos/${ctx.repo}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${ctx.token}`,
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": TOOL_NAME,
      ...(body ? { "content-type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  if (!res.ok) {
    // GitHub's error message only; never echo the request (it carries the token in a header).
    const msg = await res.json().then((j: any) => String(j?.message ?? ""), () => "");
    throw new GitHubError(res.status, `${method} ${path.split("?")[0]} → ${res.status} ${msg}`.trim());
  }
  return res.status === 204 ? undefined : res.json();
}

async function paged(ctx: Ctx, path: string, maxPages = 30): Promise<any[]> {
  const all: any[] = [];
  for (let page = 1; page <= maxPages; page++) {
    const batch: any[] = await gh(ctx, "GET", `${path}${path.includes("?") ? "&" : "?"}per_page=100&page=${page}`);
    all.push(...batch);
    if (batch.length < 100) break;
  }
  return all;
}

export async function postCheckRun(ctx: Ctx, headSha: string, items: ReportItem[], exitCode: number): Promise<void> {
  const out = checkOutput(items, exitCode);
  const anns = annotations(items);
  const first = anns.slice(0, ANNOTATION_BATCH);
  const output = { title: out.title, summary: out.summary };
  const run = await gh(ctx, "POST", "/check-runs", {
    name: "Vigil",
    head_sha: headSha,
    status: "completed",
    conclusion: out.conclusion,
    output: { ...output, annotations: first },
  });
  for (let i = ANNOTATION_BATCH; i < anns.length; i += ANNOTATION_BATCH) {
    await gh(ctx, "PATCH", `/check-runs/${run.id}`, { output: { ...output, annotations: anns.slice(i, i + ANNOTATION_BATCH) } });
  }
}

export async function postReview(
  ctx: Ctx,
  pr: { number: number; headSha: string },
  items: ReportItem[],
  minSeverity: Severity,
): Promise<{ posted: number; skipped: number }> {
  const files = await paged(ctx, `/pulls/${pr.number}/files`);
  const added = new Map<string, Set<number>>();
  for (const f of files) if (typeof f.patch === "string" && f.status !== "removed") added.set(f.filename, addedLines(f.patch));

  const existing = await paged(ctx, `/pulls/${pr.number}/comments`);
  const done = new Set<string>();
  for (const c of existing) {
    const m = MARKER.exec(String(c.body ?? ""));
    if (m) done.add(m[1]!);
  }

  const { comments, skipped } = selectComments(items, added, done, minSeverity);
  if (comments.length === 0) return { posted: 0, skipped };
  const more = skipped ? `\n\n${skipped} more new finding${skipped === 1 ? "" : "s"} on changed lines: see the Vigil check run.` : "";
  await gh(ctx, "POST", `/pulls/${pr.number}/reviews`, {
    commit_id: pr.headSha,
    event: "COMMENT",
    body: `${TOOL_NAME} found ${comments.length + skipped} new issue${comments.length + skipped === 1 ? "" : "s"} on lines this pull request adds.${more}`,
    comments: comments.map((f) => ({ path: f.path, line: f.line, side: "RIGHT", body: commentBody(f) })),
  });
  return { posted: comments.length, skipped };
}

export interface ReportOptions {
  ctx: Ctx;
  event: any;
  sha: string;
  items: ReportItem[];
  exitCode: number;
  checkRun: boolean;
  prComments: boolean;
  minSeverity: Severity;
  log: (line: string) => void;
}

/** Never throws for GitHub errors: the gate is a separate step. Returns lines for the log. */
export async function report(o: ReportOptions): Promise<void> {
  const pr = o.event?.pull_request;
  const headSha: string = pr?.head?.sha ?? o.sha;
  const permHint = (what: string, perm: string, e: unknown) => {
    if (e instanceof GitHubError && (e.status === 403 || e.status === 404)) {
      o.log(`::notice::Vigil skipped the ${what}: the token lacks \`${perm}\` (fork pull requests never have it).`);
    } else {
      o.log(`::warning::Vigil could not post the ${what}: ${e instanceof Error ? e.message : String(e)}`);
    }
  };
  if (o.checkRun) {
    try {
      await postCheckRun(o.ctx, headSha, o.items, o.exitCode);
      o.log(`Vigil: check run posted (${Math.min(o.items.length, MAX_ANNOTATIONS)} annotations).`);
    } catch (e) {
      permHint("check run", "checks: write", e);
    }
  }
  if (o.prComments && pr?.number) {
    try {
      const r = await postReview(o.ctx, { number: pr.number, headSha }, o.items, o.minSeverity);
      o.log(`Vigil: ${r.posted} new review comment${r.posted === 1 ? "" : "s"}${r.skipped ? ` (${r.skipped} over the cap)` : ""}.`);
    } catch (e) {
      permHint("pull request comments", "pull-requests: write", e);
    }
  }
}
