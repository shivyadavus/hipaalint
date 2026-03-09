declare module '@hipaalint/ai' {
  export type SensitivityLevel = 'strict' | 'balanced' | 'relaxed';
  export type ScoreBand = 'strong' | 'needs_improvement' | 'at_risk' | 'critical';
  export interface ComplianceFinding {
    ruleId: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    category: string;
    title: string;
    description: string;
    filePath: string;
    lineNumber: number;
    columnNumber: number;
    codeSnippet: string;
    citation: string;
    remediation: string;
    confidence: 'high' | 'medium' | 'low';
  }
  export interface ScanResult {
    findings: ComplianceFinding[];
    filesScanned: number;
    filesSkipped: number;
    rulesEvaluated: number;
    scanDurationMs: number;
    timestamp: string;
  }
  export interface ComplianceScore {
    overallScore: number;
    band: ScoreBand;
    metadata: {
      scannedAt: string;
      framework: string;
    };
  }
  export interface HipaaLintConfig {
    sensitivity?: SensitivityLevel;
    frameworks?: string[];
    ignore?: string[];
    threshold?: number;
    maxFiles?: number;
    maxDepth?: number;
    timeout?: number;
  }
  export class RuleEvaluator {
    constructor(options?: { sensitivity?: SensitivityLevel });
    evaluate(
      paths: string[],
      framework?: string,
      options?: { ignore?: string[]; maxFiles?: number; maxDepth?: number; timeoutMs?: number },
    ): ScanResult;
    close(): void;
  }
  export class ScoreCalculator {
    calculateScore(
      scanResult: ScanResult,
      framework?: string,
      sensitivity?: SensitivityLevel,
    ): ComplianceScore;
  }
  export function countFindings(scanResult: ScanResult['findings']): {
    bySeverity: Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>;
  };
  export function loadConfig(startDir: string, explicitConfigPath?: string): HipaaLintConfig;
  export function mergeWithFlags(
    config: HipaaLintConfig,
    flags: {
      sensitivity?: SensitivityLevel;
      framework?: string;
      exclude?: string[];
      maxFiles?: number;
      maxDepth?: number;
      timeout?: number;
    },
  ): {
    sensitivity: SensitivityLevel;
    framework: string;
    ignore: string[];
    maxFiles: number;
    maxDepth: number;
    timeout: number;
    threshold: number;
  };
}
