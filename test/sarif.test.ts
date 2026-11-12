import { describe, expect, it } from "vitest";
import type { Finding } from "../src/core/finding.js";
import { toSarif } from "../src/report/sarif.js";
import type { ScanResult } from "../src/scan.js";

const base: Finding = {
  id: "f1",
  category: "code",
  engine: "opengrep",
  ruleId: "js-sql-injection",
  title: "SQL injection",
  message: "msg",
  severity: "high",
  location: { path: "src/db.js", startLine: 5, endLine: 5, startColumn: 3 },
  cwe: ["CWE-89"],
  owasp: [],
  dataflow: [
    { path: "src/db.js", line: 1, snippet: "req.query.id" },
    { path: "src/db.js", line: 5, snippet: "db.query(sql)" },
  ],
};

function sarif(findings: Finding[]) {
  const result: ScanResult = { root: "/repo", findings, ignores: [], warnings: [], engines: [] };
  return toSarif(result) as any;
}

describe("toSarif", () => {
  it("emits one rule per engine/ruleId and links results to it", () => {
    const out = sarif([base, { ...base, id: "f2", location: { path: "src/db.js", startLine: 9 } }]);
    const run = out.runs[0];
    expect(out.version).toBe("2.1.0");
    expect(run.tool.driver.rules).toHaveLength(1);
    expect(run.tool.driver.rules[0].id).toBe("opengrep/js-sql-injection");
    expect(run.tool.driver.rules[0].properties.tags).toContain("external/cwe/cwe-89");
    expect(run.results.map((r: { ruleIndex: number }) => r.ruleIndex)).toEqual([0, 0]);
  });

  it("carries fingerprints, severity and code flows", () => {
    const r = sarif([base]).runs[0].results[0];
    expect(r.level).toBe("error");
    expect(r.partialFingerprints["vigil/v1"]).toBe("f1");
    expect(r.locations[0].physicalLocation.region).toEqual({ startLine: 5, endLine: 5, startColumn: 3 });
    expect(r.codeFlows[0].threadFlows[0].locations).toHaveLength(2);
  });

  it("omits codeFlows when there is no dataflow", () => {
    const { dataflow: _, ...noFlow } = base;
    expect(sarif([noFlow]).runs[0].results[0].codeFlows).toBeUndefined();
  });
});
