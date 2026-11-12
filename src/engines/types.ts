import type { Finding } from "../core/finding.js";

export interface EngineOutput {
  findings: Finding[];
  warnings: string[];
}
