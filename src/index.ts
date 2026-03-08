// HipaaLint AI — Public API
// Barrel export for library consumers

export { PHIDetector } from './engine/phi-detector.js';
export { RuleEvaluator } from './engine/rule-evaluator.js';
export { ScoreCalculator } from './engine/score-calculator.js';
export { RegexCache } from './engine/regex-cache.js';
export { countFindings } from './engine/finding-counter.js';
export type { FindingCounts } from './engine/finding-counter.js';
export { AutoFixer, getFixableRuleIds } from './engine/auto-fixer.js';
export type { FixResult, FixSummary } from './engine/auto-fixer.js';
export { loadConfig, mergeWithFlags, HipaaLintConfigSchema } from './engine/config-loader.js';
export type { HipaaLintConfig } from './engine/config-loader.js';
export { analyzeTaint } from './engine/taint-tracker.js';
export { RuleDatabase } from './rules/rule-loader.js';
export { generateJsonReport, generateSarifReport } from './reports/json-report.js';
export { generatePdfReport } from './reports/pdf-report.js';
export {
  generateBadgeUrl,
  generateBadgeMarkdown,
  generateBadgeSvg,
} from './reports/badge-generator.js';
export { buildReport, generateRecommendations } from './reports/report-builder.js';
export { VERSION, RULES_VERSION } from './version.js';

// Security
export {
  SecurityError,
  validateScanPath,
  validateOutputDirectory,
  isSymlink,
  sanitizeFilename,
  createSafeRegex,
  isReDoSVulnerable,
} from './security/index.js';

// Re-export types
export type {
  ComplianceFinding,
  ComplianceScore,
  ComplianceReport,
  DomainScore,
  ScanResult,
  Rule,
  Framework,
  Checkpoint,
  PHIFinding,
  SensitivityLevel,
  Severity,
  Category,
  ScoreBand,
  PHIIdentifierType,
} from './engine/types.js';
