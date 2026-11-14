import { describe, expect, it } from "vitest";
import {
  addedLines,
  annotations,
  commentBody,
  itemsFromSarif,
  MAX_COMMENTS,
  report,
  safeText,
  selectComments,
  type Ctx,
  type ReportItem,
} from "../src/action/github.js";
import type { Finding } from "../src/core/finding.js";
import { toSarif } from "../src/report/sarif.js";

function finding(over: Partial<Finding> & { id: string; path: string; line: number }): Finding {
  return {
    id: over.id,
    engine: "opengrep",
    ruleId: over.ruleId ?? "js-sql-injection",
    title: over.title ?? "SQL injection",
    message: over.message ?? "User input reaches a SQL query.",
    severity: over.severity ?? "high",
    category: "code",
    cwe: ["CWE-89"],
    owasp: [],
    location: { path: over.path, startLine: over.line },
    ...(over.reachability ? { reachability: over.reachability } : {}),
  } as Finding;
}

const sarifOf = (fs: Finding[]) => toSarif({ findings: fs } as any);

function item(id: string, path: string, line: number, severity: ReportItem["severity"] = "high"): ReportItem {
  return { id, ruleId: "r", title: "t", severity, message: "m", path, line };
}

describe("itemsFromSarif", () => {
  it("round-trips Finding fields, sorts by severity, prefixes paths", () => {
    const items = itemsFromSarif(
      sarifOf([
        finding({ id: "a", path: "src/x.js", line: 3, severity: "low" }),
        finding({ id: "b", path: "y.py", line: 7, severity: "critical" }),
        finding({ id: "c", path: "z.js", line: 1, severity: "medium", reachability: { status: "unreachable", reason: "r" } as any }),
      ]),
      "services/api/",
    );
    expect(items.map((i) => [i.id, i.severity, i.path, i.line])).toEqual([
      ["b", "critical", "services/api/y.py", 7],
      ["c", "medium", "services/api/z.js", 1],
      ["a", "low", "services/api/src/x.js", 3],
    ]);
    expect(items[1]!.reachability).toBe("unreachable");
    expect(itemsFromSarif(sarifOf([finding({ id: "a", path: "x.js", line: 1 })]), "")[0]!.path).toBe("x.js");
  });
});

describe("addedLines", () => {
  it("tracks new-side line numbers across hunks", () => {
    const patch = ["@@ -1,3 +1,4 @@", " a", "-b", "+B", "+C", " d", "@@ -20,2 +21,3 @@", " x", "+y", "\\ No newline at end of file"].join("\n");
    expect([...addedLines(patch)]).toEqual([2, 3, 22]);
  });
});

describe("selectComments", () => {
  const added = new Map([["a.js", new Set([5, 6])]]);
  it("keeps added lines at or above the threshold that aren't already commented", () => {
    const items = [item("1", "a.js", 5), item("2", "a.js", 7), item("3", "b.js", 5), item("4", "a.js", 6, "low"), item("5", "a.js", 6)];
    expect(selectComments(items, added, new Set(["5"]), "medium").comments.map((c) => c.id)).toEqual(["1"]);
  });
  it("caps the number of comments", () => {
    const many = Array.from({ length: MAX_COMMENTS + 3 }, (_, i) => item(String(i), "a.js", 5));
    const r = selectComments(many, added, new Set(), "info");
    expect(r.comments).toHaveLength(MAX_COMMENTS);
    expect(r.skipped).toBe(3);
  });
});

describe("untrusted text", () => {
  it("neutralises HTML, mentions, issue refs and code spans", () => {
    const s = safeText("<img src=x> @octocat #12 `x` a&b");
    expect(s).not.toMatch(/<|@o|#1|`/);
    expect(s).toContain("&lt;img");
    expect(s).toContain("&amp;");
  });
  it("carries one marker with a sanitised fingerprint", () => {
    const body = commentBody({ ...item("ab-->c", "a.js", 1), message: "@team <b>hi</b>" });
    expect(body).toContain("<!-- vigil:abc -->");
    expect(body.match(/<!--/g)).toHaveLength(1);
    expect(body).not.toContain("@team");
  });
});

describe("annotations", () => {
  it("maps severity to annotation level", () => {
    const a = annotations([item("1", "a", 1, "critical"), item("2", "a", 2, "medium"), item("3", "a", 3, "info")]) as any[];
    expect(a.map((x) => x.annotation_level)).toEqual(["failure", "warning", "notice"]);
  });
});

// ---- network, with a fake fetch --------------------------------------------------------------

type Call = { method: string; url: string; body?: any };
function fakeGitHub(routes: Record<string, (call: Call) => { status?: number; json?: unknown }>) {
  const calls: Call[] = [];
  const f = (async (url: string, init: RequestInit) => {
    const call = { method: init.method!, url, body: init.body ? JSON.parse(String(init.body)) : undefined };
    calls.push(call);
    const key = Object.keys(routes).find((k) => `${call.method} ${url}`.includes(k));
    const r = key ? routes[key]!(call) : { status: 404, json: { message: "Not Found" } };
    const status = r.status ?? 200;
    return new Response(JSON.stringify(r.json ?? {}), { status });
  }) as unknown as typeof fetch;
  const ctx: Ctx = { api: "https://api.test", repo: "o/r", token: "t", fetch: f };
  return { ctx, calls };
}

const prEvent = { pull_request: { number: 7, head: { sha: "HEAD" } } };

describe("report", () => {
  it("posts a check run in annotation batches and one review for new findings", async () => {
    const items = [...Array.from({ length: 120 }, (_, i) => item(`n${i}`, "old.js", i + 1, "low")), item("new", "a.js", 2), item("seen", "a.js", 3)];
    const { ctx, calls } = fakeGitHub({
      "POST https://api.test/repos/o/r/check-runs": () => ({ json: { id: 99 } }),
      "PATCH https://api.test/repos/o/r/check-runs/99": () => ({}),
      "/pulls/7/files": () => ({ json: [{ filename: "a.js", status: "modified", patch: "@@ -1,1 +1,3 @@\n x\n+y\n+z" }] }),
      "/pulls/7/comments": () => ({ json: [{ body: "old\n<!-- vigil:seen -->" }] }),
      "POST https://api.test/repos/o/r/pulls/7/reviews": () => ({}),
    });
    const log: string[] = [];
    await report({ ctx, event: prEvent, sha: "MERGE", items, exitCode: 1, checkRun: true, prComments: true, minSeverity: "medium", log: (l) => log.push(l) });

    const create = calls.find((c) => c.method === "POST" && c.url.endsWith("/check-runs"))!;
    expect(create.body).toMatchObject({ name: "Vigil", head_sha: "HEAD", conclusion: "failure" });
    expect(create.body.output.annotations).toHaveLength(50);
    expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(2); // 122 annotations → 50 + 50 + 22
    const review = calls.find((c) => c.url.endsWith("/reviews"))!;
    expect(review.body.commit_id).toBe("HEAD");
    expect(review.body.comments).toEqual([expect.objectContaining({ path: "a.js", line: 2, side: "RIGHT" })]);
    expect(log.join("\n")).not.toMatch(/warning/);
  });

  it("turns missing permissions into a notice, and skips comments outside PRs", async () => {
    const { ctx, calls } = fakeGitHub({ "/check-runs": () => ({ status: 403, json: { message: "Resource not accessible by integration" } }) });
    const log: string[] = [];
    await report({ ctx, event: {}, sha: "SHA", items: [item("1", "a.js", 1)], exitCode: 0, checkRun: true, prComments: true, minSeverity: "medium", log: (l) => log.push(l) });
    expect(log).toEqual([expect.stringMatching(/^::notice::.*checks: write/)]);
    expect(calls.every((c) => !c.url.includes("/pulls/"))).toBe(true);
  });

  it("posts no review when nothing new is on an added line", async () => {
    const { ctx, calls } = fakeGitHub({
      "/pulls/7/files": () => ({ json: [{ filename: "a.js", status: "modified", patch: "@@ -1 +1 @@\n-a\n+b" }] }),
      "/pulls/7/comments": () => ({ json: [] }),
    });
    await report({ ctx, event: prEvent, sha: "M", items: [item("1", "a.js", 9)], exitCode: 0, checkRun: false, prComments: true, minSeverity: "medium", log: () => {} });
    expect(calls.some((c) => c.url.endsWith("/reviews"))).toBe(false);
  });
});
