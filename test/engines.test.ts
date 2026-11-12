import { describe, expect, it } from "vitest";
import { normalizeGitleaks, type GitleaksLeak } from "../src/engines/gitleaks.js";
import { normalizeOpengrep, ruleIdOf, type OgOutput } from "../src/engines/opengrep.js";
import { normalizeOsv, severityFromScore, type OsvOutput } from "../src/engines/osv.js";

const ROOT = "/repo";

describe("opengrep normalizer", () => {
  const result = (line: number, lines: string): OgOutput["results"][number] => ({
    check_id: "Users.x.rules.javascript.js-sql-injection",
    path: "/repo/src/db.js",
    start: { line, col: 3 },
    end: { line, col: 40 },
    extra: {
      message: "  SQL built from request input.  ",
      severity: "ERROR",
      lines,
      metadata: {
        title: "SQL injection",
        cwe: ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
        owasp: "A03:2021 - Injection",
        confidence: "HIGH",
      },
      dataflow_trace: {
        taint_source: ["CliLoc", [{ path: "/repo/src/db.js", start: { line: 1, col: 1 }, end: { line: 1, col: 9 } }, "req.query.id"]],
        taint_sink: ["CliLoc", [{ path: "/repo/src/db.js", start: { line, col: 3 }, end: { line, col: 9 } }, "db.query(sql)"]],
      },
    },
  });

  it("strips the config path from rule ids", () => {
    expect(ruleIdOf("a.b.c.js-sql-injection")).toBe("js-sql-injection");
  });

  it("maps fields into a Finding", () => {
    const [f] = normalizeOpengrep(ROOT, { results: [result(5, "db.query(sql)")], errors: [] });
    expect(f).toMatchObject({
      category: "code",
      engine: "opengrep",
      ruleId: "js-sql-injection",
      title: "SQL injection",
      message: "SQL built from request input.",
      severity: "high",
      confidence: "high",
      location: { path: "src/db.js", startLine: 5, startColumn: 3 },
      cwe: ["CWE-89"],
      owasp: ["A03:2021 - Injection"],
    });
    expect(f?.dataflow?.map((s) => s.line)).toEqual([1, 5]);
  });

  it("keeps fingerprints stable across line moves and reformatting", () => {
    const [a] = normalizeOpengrep(ROOT, { results: [result(5, "db.query(sql)")], errors: [] });
    const [b] = normalizeOpengrep(ROOT, { results: [result(42, "db.query(  sql )")], errors: [] });
    expect(a?.id).toBe(b?.id);
  });

  it("gives identical code on different lines distinct fingerprints", () => {
    const fs = normalizeOpengrep(ROOT, { results: [result(5, "db.query(sql)"), result(9, "db.query(sql)")], errors: [] });
    expect(new Set(fs.map((f) => f.id)).size).toBe(2);
  });

  it("reports a sink once when several taint sources reach the same range", () => {
    const fs = normalizeOpengrep(ROOT, { results: [result(5, "db.query(sql)"), result(5, "db.query(sql)")], errors: [] });
    expect(fs).toHaveLength(1);
  });
});

describe("osv normalizer", () => {
  const out: OsvOutput = {
    results: [
      {
        source: { path: "/repo/package-lock.json", type: "lockfile" },
        packages: [
          {
            package: { name: "lodash", version: "4.17.20", ecosystem: "npm" },
            vulnerabilities: [
              {
                id: "GHSA-35jh-r3h4-6jhm",
                summary: "Command Injection in lodash",
                aliases: ["CVE-2021-23337"],
                affected: [{ package: { name: "lodash" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
                database_specific: { severity: "HIGH", cwe_ids: ["CWE-77"] },
              },
            ],
            groups: [{ ids: ["GHSA-35jh-r3h4-6jhm"], aliases: ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"], max_severity: "7.2" }],
          },
        ],
      },
    ],
  };

  it("emits one finding per advisory group with fix versions", () => {
    const [f, ...rest] = normalizeOsv(ROOT, out);
    expect(rest).toHaveLength(0);
    expect(f).toMatchObject({
      category: "dependency",
      ruleId: "GHSA-35jh-r3h4-6jhm",
      severity: "high",
      location: { path: "package-lock.json", startLine: 1 },
      cwe: ["CWE-77"],
      dependency: { name: "lodash", version: "4.17.20", advisories: ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"], fixedVersions: ["4.17.21"] },
    });
    expect(f?.message).toContain("Upgrade to 4.17.21");
  });

  it("maps CVSS scores, then labels, to severity", () => {
    expect(severityFromScore("9.8", undefined)).toBe("critical");
    expect(severityFromScore("4.0", "HIGH")).toBe("medium");
    expect(severityFromScore(undefined, "LOW")).toBe("low");
    expect(severityFromScore("", undefined)).toBe("medium");
  });
});

describe("gitleaks normalizer", () => {
  // Built at runtime so this fake token is not itself a literal secret in the repo.
  const secret = ["ghp", "R4nd0mT0k3nV4lu3ThatIsLong1234567890"].join("_");
  const leak: GitleaksLeak = {
    RuleID: "github-pat",
    Description: "GitHub Personal Access Token.",
    StartLine: 3,
    EndLine: 3,
    StartColumn: 14,
    Match: `const token = "${secret}";`,
    Secret: secret,
    File: "/repo/src/config.js",
  };

  it("never puts the raw secret into the Finding", () => {
    const findings = normalizeGitleaks(ROOT, [leak]);
    const serialized = JSON.stringify(findings);
    expect(serialized).not.toContain(secret);
    expect(serialized).not.toContain(secret.slice(4, 20));
    expect(findings[0]?.location.snippet).toContain("ghp_");
  });

  it("rates generic heuristics lower than provider-specific rules", () => {
    const [specific] = normalizeGitleaks(ROOT, [leak]);
    const [generic] = normalizeGitleaks(ROOT, [{ ...leak, RuleID: "generic-api-key" }]);
    expect(specific).toMatchObject({ severity: "high", confidence: "high" });
    expect(generic).toMatchObject({ severity: "medium", confidence: "medium" });
  });

  it("fingerprints on the secret, not its line", () => {
    const [a] = normalizeGitleaks(ROOT, [leak]);
    const [b] = normalizeGitleaks(ROOT, [{ ...leak, StartLine: 80, EndLine: 80 }]);
    expect(a?.id).toBe(b?.id);
  });
});
