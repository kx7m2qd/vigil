import type { Finding, Severity } from "../core/finding.js";
import { TOOL_NAME, TOOL_URI, TOOL_VERSION } from "../version.js";
import type { ScanResult } from "../scan.js";

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

/** GitHub code scanning reads this to bucket alerts into critical/high/medium/low. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
  info: "0.0",
};

function ruleKey(f: Finding): string {
  return `${f.engine}/${f.ruleId}`;
}

export function toSarif(result: ScanResult): object {
  const rules = new Map<string, Finding>();
  for (const f of result.findings) if (!rules.has(ruleKey(f))) rules.set(ruleKey(f), f);
  const ruleIndex = new Map([...rules.keys()].map((k, i) => [k, i]));

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri: TOOL_URI,
            rules: [...rules.entries()].map(([key, f]) => ({
              id: key,
              name: f.ruleId,
              shortDescription: { text: f.title },
              fullDescription: { text: f.category === "dependency" ? f.title : f.message },
              defaultConfiguration: { level: LEVEL[f.severity] },
              properties: {
                "security-severity": SECURITY_SEVERITY[f.severity],
                tags: ["security", f.category, ...f.cwe.map((c) => `external/cwe/${c.toLowerCase()}`)],
              },
            })),
          },
        },
        results: result.findings.map((f) => ({
          ruleId: ruleKey(f),
          ruleIndex: ruleIndex.get(ruleKey(f)),
          level: LEVEL[f.severity],
          message: { text: f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.location.path, uriBaseId: "%SRCROOT%" },
                region: {
                  startLine: f.location.startLine,
                  ...(f.location.endLine ? { endLine: f.location.endLine } : {}),
                  ...(f.location.startColumn ? { startColumn: f.location.startColumn } : {}),
                },
              },
            },
          ],
          partialFingerprints: { [`${TOOL_NAME}/v1`]: f.id },
          // Findings sharing a rule can differ in severity (reachability lowers it per finding).
          properties: {
            severity: f.severity,
            ...(f.reachability
              ? {
                  reachability: f.reachability.status,
                  reachabilityReason: f.reachability.reason,
                  ...(f.reachability.originalSeverity ? { originalSeverity: f.reachability.originalSeverity } : {}),
                }
              : {}),
          },
          ...(f.dataflow
            ? {
                codeFlows: [
                  {
                    threadFlows: [
                      {
                        locations: f.dataflow.map((s) => ({
                          location: {
                            physicalLocation: {
                              artifactLocation: { uri: s.path, uriBaseId: "%SRCROOT%" },
                              region: { startLine: s.line },
                            },
                            message: { text: s.snippet ?? "" },
                          },
                        })),
                      },
                    ],
                  },
                ],
              }
            : {}),
        })),
      },
    ],
  };
}
