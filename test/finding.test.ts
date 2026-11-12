import { describe, expect, it } from "vitest";
import {
  collapseOverlaps,
  dedupe,
  fingerprint,
  normalizeCode,
  redactSecret,
  severityAtLeast,
  sortFindings,
  type Finding,
} from "../src/core/finding.js";

function finding(over: Partial<Finding> & { path?: string; line?: number } = {}): Finding {
  const { path = "a.js", line = 1, ...rest } = over;
  return {
    id: fingerprint(path, String(line), rest.severity ?? "high"),
    category: "code",
    engine: "opengrep",
    ruleId: "js-test",
    title: "t",
    message: "m",
    severity: "high",
    location: { path, startLine: line },
    cwe: [],
    owasp: [],
    ...rest,
  };
}

describe("fingerprint", () => {
  it("is stable and 32 hex chars", () => {
    expect(fingerprint("a", "b")).toBe(fingerprint("a", "b"));
    expect(fingerprint("a", "b")).toMatch(/^[0-9a-f]{32}$/);
  });

  it("does not collide when parts shift between fields", () => {
    expect(fingerprint("ab", "c")).not.toBe(fingerprint("a", "bc"));
  });
});

describe("normalizeCode", () => {
  it("ignores reformatting", () => {
    expect(normalizeCode("  db.query(\n\t sql\n)  ")).toBe(normalizeCode("db.query(sql)"));
  });
});

describe("redactSecret", () => {
  it("fully masks short values", () => {
    expect(redactSecret("abc123")).toBe("******");
  });

  it("keeps only a 4-char prefix of long values", () => {
    const secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    const out = redactSecret(secret);
    expect(out.startsWith("ghp_")).toBe(true);
    expect(out).not.toContain(secret.slice(4, 10));
    expect(out.length).toBeLessThanOrEqual(16);
  });
});

describe("severityAtLeast", () => {
  it("orders critical above info", () => {
    expect(severityAtLeast("critical", "high")).toBe(true);
    expect(severityAtLeast("high", "high")).toBe(true);
    expect(severityAtLeast("medium", "high")).toBe(false);
  });
});

describe("sortFindings / dedupe", () => {
  it("sorts by severity, then path, then line", () => {
    const sorted = sortFindings([
      finding({ severity: "low", path: "a.js" }),
      finding({ severity: "high", path: "b.js", line: 9 }),
      finding({ severity: "high", path: "b.js", line: 2 }),
      finding({ severity: "critical", path: "z.js" }),
    ]);
    expect(sorted.map((f) => `${f.severity}:${f.location.path}:${f.location.startLine}`)).toEqual([
      "critical:z.js:1",
      "high:b.js:2",
      "high:b.js:9",
      "low:a.js:1",
    ]);
  });

  it("keeps the first of each fingerprint", () => {
    const a = finding({ title: "first" });
    const b = { ...a, title: "second" };
    expect(dedupe([a, b])).toEqual([a]);
  });
});

describe("collapseOverlaps", () => {
  const taint = finding({ ruleId: "py-sql-injection", cwe: ["CWE-89"], confidence: "high", line: 5 });
  const pattern = finding({ ruleId: "py-sql-formatted-query", cwe: ["CWE-89"], confidence: "medium", line: 5 });

  it("keeps the more confident of two same-CWE findings on one line, in either order", () => {
    expect(collapseOverlaps([pattern, taint])).toEqual([taint]);
    expect(collapseOverlaps([taint, pattern])).toEqual([taint]);
  });

  it("prefers a finding with a dataflow trace when confidence ties", () => {
    const traced = { ...pattern, ruleId: "py-other", dataflow: [{ path: "a.js", line: 5 }] };
    expect(collapseOverlaps([pattern, traced])).toEqual([traced]);
  });

  it("keeps findings on other lines, with other CWEs, or from the same rule", () => {
    const otherLine = { ...pattern, location: { path: "a.js", startLine: 6 } };
    const otherCwe = { ...pattern, cwe: ["CWE-78"] };
    const sameRule = { ...taint, id: "second" };
    expect(collapseOverlaps([taint, otherLine, otherCwe, sameRule])).toEqual([taint, otherLine, otherCwe, sameRule]);
  });
});
