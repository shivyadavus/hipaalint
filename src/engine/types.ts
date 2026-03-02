import { z } from 'zod';

// ──────────────────────────────────────────────────
// Enums
// ──────────────────────────────────────────────────

export const Severity = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export type Severity = z.infer<typeof Severity>;

export const Category = z.enum([
  'phi_protection',
  'encryption',
  'access_control',
  'audit_logging',
  'infrastructure',
  'ai_governance',
]);
export type Category = z.infer<typeof Category>;

export const PatternType = z.enum([
  'code_pattern',
  'ast_pattern',
  'config_pattern',
  'import_pattern',
  'negative_pattern',
]);
export type PatternType = z.infer<typeof PatternType>;

export const ScoreBand = z.enum(['compliant', 'needs_improvement', 'at_risk', 'critical']);
export type ScoreBand = z.infer<typeof ScoreBand>;

export const ReportFormat = z.enum(['json', 'pdf', 'sarif']);
export type ReportFormat = z.infer<typeof ReportFormat>;

export const SensitivityLevel = z.enum(['strict', 'balanced', 'relaxed']);
export type SensitivityLevel = z.infer<typeof SensitivityLevel>;

export const SupportedLanguage = z.enum(['typescript', 'javascript', 'python']);
export type SupportedLanguage = z.infer<typeof SupportedLanguage>;

// ──────────────────────────────────────────────────
// Rule Database Types
// ──────────────────────────────────────────────────

export const FrameworkSchema = z.object({
  id: z.number(),
  name: z.string(),
  version: z.string(),
  description: z.string(),
  sourceUrl: z.string().url().optional(),
});
export type Framework = z.infer<typeof FrameworkSchema>;

export const RuleSchema = z.object({
  id: z.number(),
  frameworkId: z.number(),
  ruleId: z.string(),
  title: z.string(),
  description: z.string(),
  severity: Severity,
  category: Category,
  citation: z.string(),
  remediation: z.string(),
  patternType: PatternType,
  patternConfig: z.string(), // JSON-encoded pattern configuration
  isRequired: z.boolean(),
});
export type Rule = z.infer<typeof RuleSchema>;

export const CheckpointSchema = z.object({
  id: z.number(),
  ruleId: z.number(),
  checkpointType: z.string(),
  configJson: z.string(),
});
export type Checkpoint = z.infer<typeof CheckpointSchema>;

// ──────────────────────────────────────────────────
// Finding Types
// ──────────────────────────────────────────────────

export const ComplianceFindingSchema = z.object({
  ruleId: z.string(),
  frameworkId: z.string(),
  severity: Severity,
  category: Category,
  title: z.string(),
  description: z.string(),
  filePath: z.string(),
  lineNumber: z.number(),
  columnNumber: z.number(),
  codeSnippet: z.string(), // sanitized — no PHI
  citation: z.string(),
  remediation: z.string(),
  confidence: z.enum(['high', 'medium', 'low']),
  context: z.string().optional(), // e.g., "log_statement", "api_response"
  timestamp: z.string().datetime(),
});
export type ComplianceFinding = z.infer<typeof ComplianceFindingSchema>;

// ──────────────────────────────────────────────────
// PHI Detection Types
// ──────────────────────────────────────────────────

export const PHIIdentifierType = z.enum([
  'name',
  'ssn',
  'date_of_birth',
  'address',
  'phone',
  'email',
  'medical_record_number',
  'health_plan_beneficiary',
  'account_number',
  'certificate_license',
  'vehicle_identifier',
  'device_identifier',
  'url',
  'ip_address',
  'biometric',
  'photo',
  'other_unique_identifier',
  'fax',
]);
export type PHIIdentifierType = z.infer<typeof PHIIdentifierType>;

export const PHIFindingSchema = z.object({
  identifierType: PHIIdentifierType,
  filePath: z.string(),
  lineNumber: z.number(),
  columnNumber: z.number(),
  matchedText: z.string(), // partial match, redacted for display
  context: z.enum([
    'log_statement',
    'variable_declaration',
    'string_literal',
    'api_response',
    'database_query',
    'error_handler',
    'test_fixture',
    'comment',
    'config_file',
    'other',
  ]),
  confidence: z.enum(['high', 'medium', 'low']),
  citation: z.string(),
});
export type PHIFinding = z.infer<typeof PHIFindingSchema>;

// ──────────────────────────────────────────────────
// Score Types
// ──────────────────────────────────────────────────

export const DomainScoreSchema = z.object({
  score: z.number().min(0).max(100),
  weight: z.number(),
  totalCheckpoints: z.number(),
  passedCheckpoints: z.number(),
  failedCheckpoints: z.number(),
  warningCheckpoints: z.number(),
  findings: z.array(ComplianceFindingSchema),
});
export type DomainScore = z.infer<typeof DomainScoreSchema>;

export const ComplianceScoreSchema = z.object({
  overallScore: z.number().min(0).max(100),
  band: ScoreBand,
  domainScores: z.object({
    phiProtection: DomainScoreSchema,
    encryption: DomainScoreSchema,
    accessControl: DomainScoreSchema,
    auditLogging: DomainScoreSchema,
    infrastructure: DomainScoreSchema,
    aiGovernance: DomainScoreSchema,
  }),
  metadata: z.object({
    scannedAt: z.string().datetime(),
    filesScanned: z.number(),
    rulesEvaluated: z.number(),
    framework: z.string(),
    sensitivity: SensitivityLevel,
    engineVersion: z.string(),
  }),
});
export type ComplianceScore = z.infer<typeof ComplianceScoreSchema>;

// ──────────────────────────────────────────────────
// Report Types
// ──────────────────────────────────────────────────

export const ComplianceReportSchema = z.object({
  id: z.string().uuid(),
  version: z.string(),
  projectName: z.string(),
  projectPath: z.string(),
  generatedAt: z.string().datetime(),
  score: ComplianceScoreSchema,
  findings: z.array(ComplianceFindingSchema),
  summary: z.object({
    totalFindings: z.number(),
    bySeverity: z.record(Severity, z.number()),
    byCategory: z.record(Category, z.number()),
  }),
  recommendations: z.array(
    z.object({
      priority: z.number().min(1).max(10),
      description: z.string(),
      affectedRules: z.array(z.string()),
    }),
  ),
  metadata: z.object({
    hipaalintVersion: z.string(),
    rulesVersion: z.string(),
    frameworksEvaluated: z.array(z.string()),
    sensitivity: SensitivityLevel,
  }),
});
export type ComplianceReport = z.infer<typeof ComplianceReportSchema>;

// ──────────────────────────────────────────────────
// Scan Request / Result Types
// ──────────────────────────────────────────────────

export const ScanRequestSchema = z.object({
  paths: z.array(z.string()).min(1),
  framework: z.string().default('hipaa'),
  sensitivity: SensitivityLevel.default('balanced'),
  ignore: z.array(z.string()).default([]),
  maxFiles: z.number().default(10000),
});
export type ScanRequest = z.infer<typeof ScanRequestSchema>;

export const ScanResultSchema = z.object({
  findings: z.array(ComplianceFindingSchema),
  filesScanned: z.number(),
  filesSkipped: z.number(),
  rulesEvaluated: z.number(),
  scanDurationMs: z.number(),
  timestamp: z.string().datetime(),
});
export type ScanResult = z.infer<typeof ScanResultSchema>;

// ──────────────────────────────────────────────────
// Configuration Types
// ──────────────────────────────────────────────────

export const ConfigSchema = z.object({
  frameworks: z.array(z.string()).default(['hipaa']),
  sensitivity: SensitivityLevel.default('balanced'),
  ignore: z.array(z.string()).default(['node_modules', '*.test.*', 'dist', 'coverage']),
  scoreThreshold: z.number().min(0).max(100).default(70),
  customPolicies: z.array(z.string()).default([]),
  maxFiles: z.number().default(10000),
});
export type Config = z.infer<typeof ConfigSchema>;

// ──────────────────────────────────────────────────
// Domain weight constants
// ──────────────────────────────────────────────────

export const DOMAIN_WEIGHTS: Record<keyof ComplianceScore['domainScores'], number> = {
  phiProtection: 0.25,
  encryption: 0.2,
  accessControl: 0.2,
  auditLogging: 0.15,
  infrastructure: 0.1,
  aiGovernance: 0.1,
};

export const SCORE_BAND_THRESHOLDS = {
  compliant: 90,
  needs_improvement: 70,
  at_risk: 40,
  critical: 0,
} as const;

export const SCORE_CLAMP_RULES = {
  criticalPHIFinding: 69,
  noEncryptionAtRest: 59,
  noMFAEnforcement: 79,
} as const;
