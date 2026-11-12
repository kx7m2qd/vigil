import { describe, expect, it } from "vitest";
import { scoreCategories } from "../bench/owasp.js";
import type { Finding } from "../src/core/finding.js";

const finding = (path: string, cwe: string): Finding => ({
  id: path,
  category: "code",
  engine: "opengrep",
  ruleId: "py-sql-injection",
  title: "t",
  message: "m",
  severity: "high",
  location: { path, startLine: 1 },
  cwe: [cwe],
  owasp: [],
});

describe("OWASP Benchmark scoring", () => {
  const cases = [
    { test: "BenchmarkTest00001", category: "sqli", cwe: "CWE-89", real: true },
    { test: "BenchmarkTest00002", category: "sqli", cwe: "CWE-89", real: true },
    { test: "BenchmarkTest00003", category: "sqli", cwe: "CWE-89", real: false },
    { test: "BenchmarkTest00004", category: "sqli", cwe: "CWE-89", real: false },
  ];

  it("scores TPR minus FPR per category, matching findings by test file and CWE", () => {
    const findings = [
      finding("BenchmarkTest00001.py", "CWE-89"),
      finding("BenchmarkTest00003.py", "CWE-89"),
      // Right file, wrong CWE: does not count for sqli.
      finding("BenchmarkTest00002.py", "CWE-78"),
    ];
    const s = scoreCategories(cases, findings, new Set(["CWE-89"]))["sqli"];
    expect(s).toMatchObject({ tp: 1, fn: 1, fp: 1, tn: 1, tpr: 0.5, fpr: 0.5, score: 0, covered: true });
  });

  it("does not let BenchmarkTest00001 match BenchmarkTest000010", () => {
    const s = scoreCategories(cases, [finding("BenchmarkTest000010.py", "CWE-89")], new Set())["sqli"];
    expect(s).toMatchObject({ tp: 0, covered: false });
  });
});
