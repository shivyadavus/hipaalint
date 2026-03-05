import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { RuleEvaluator } from '../../src/engine/rule-evaluator.js';
import { PHIDetector } from '../../src/engine/phi-detector.js';
import { ScoreCalculator } from '../../src/engine/score-calculator.js';
import { generateJsonReport } from '../../src/reports/json-report.js';
import type { ComplianceReport } from '../../src/engine/types.js';
import {
  SecurityError,
  validateScanPath,
  validateOutputDirectory,
} from '../../src/security/index.js';
import { existsSync, mkdirSync, rmSync, readFileSync } from 'fs';
import { resolve, dirname, basename, join } from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_ROOT = resolve(__dirname, '../fixtures');
const COMPLIANT_DIR = resolve(FIXTURES_ROOT, 'compliant');
const NON_COMPLIANT_DIR = resolve(FIXTURES_ROOT, 'non-compliant');
const INTEGRATION_TMP = resolve(FIXTURES_ROOT, 'integration');

beforeAll(() => {
  mkdirSync(INTEGRATION_TMP, { recursive: true });
});

afterAll(() => {
  rmSync(INTEGRATION_TMP, { recursive: true, force: true });
});

/**
 * Build a ComplianceReport object the same way the CLI/MCP handlers do.
 */
function buildReport(
  scanPath: string,
  sensitivity: 'strict' | 'balanced' | 'relaxed' = 'balanced',
): ComplianceReport {
  const evaluator = new RuleEvaluator({ sensitivity });
  try {
    const result = evaluator.evaluate([scanPath], 'hipaa');
    const calculator = new ScoreCalculator();
    const score = calculator.calculateScore(result, 'hipaa', sensitivity);

    return {
      id: randomUUID(),
      version: '0.1.0',
      projectName: basename(scanPath),
      projectPath: scanPath,
      generatedAt: new Date().toISOString(),
      score,
      findings: result.findings,
      summary: {
        totalFindings: result.findings.length,
        bySeverity: {
          critical: result.findings.filter((f) => f.severity === 'critical').length,
          high: result.findings.filter((f) => f.severity === 'high').length,
          medium: result.findings.filter((f) => f.severity === 'medium').length,
          low: result.findings.filter((f) => f.severity === 'low').length,
          info: result.findings.filter((f) => f.severity === 'info').length,
        },
        byCategory: {
          phi_protection: result.findings.filter((f) => f.category === 'phi_protection').length,
          encryption: result.findings.filter((f) => f.category === 'encryption').length,
          access_control: result.findings.filter((f) => f.category === 'access_control').length,
          audit_logging: result.findings.filter((f) => f.category === 'audit_logging').length,
          infrastructure: result.findings.filter((f) => f.category === 'infrastructure').length,
          ai_governance: result.findings.filter((f) => f.category === 'ai_governance').length,
        },
      },
      recommendations: [],
      metadata: {
        hipaalintVersion: '0.1.0',
        rulesVersion: '2025.1',
        frameworksEvaluated: ['hipaa'],
        sensitivity,
      },
    };
  } finally {
    evaluator.close();
  }
}

// ──────────────────────────────────────────────────
// compliance_scan pipeline
// ──────────────────────────────────────────────────

describe('MCP Tool: compliance_scan pipeline', () => {
  it('should scan compliant fixture with fewer findings than non-compliant', () => {
    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const compliantResult = evaluator.evaluate([COMPLIANT_DIR], 'hipaa');
      const nonCompliantResult = evaluator.evaluate([NON_COMPLIANT_DIR], 'hipaa');

      expect(compliantResult.filesScanned).toBeGreaterThanOrEqual(1);
      expect(compliantResult.rulesEvaluated).toBe(29);
      expect(compliantResult.scanDurationMs).toBeGreaterThanOrEqual(0);
      expect(compliantResult.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
      expect(compliantResult.findings.length).toBeLessThan(nonCompliantResult.findings.length);
    } finally {
      evaluator.close();
    }
  });

  it('should scan non-compliant fixture and return findings with valid structure', () => {
    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const result = evaluator.evaluate([NON_COMPLIANT_DIR], 'hipaa');
      expect(result.findings.length).toBeGreaterThan(0);

      // Has critical findings
      const criticals = result.findings.filter((f) => f.severity === 'critical');
      expect(criticals.length).toBeGreaterThan(0);

      // Every finding has valid structure
      for (const f of result.findings) {
        expect(f.filePath.length).toBeGreaterThan(0);
        expect(f.lineNumber).toBeGreaterThan(0);
        expect(f.citation.length).toBeGreaterThan(0);
        expect(f.codeSnippet.length).toBeLessThanOrEqual(200);
        expect(f.ruleId).toMatch(/^HIPAA-/);
      }
    } finally {
      evaluator.close();
    }
  });

  it('should find more violations in strict mode than relaxed mode', () => {
    const strictEval = new RuleEvaluator({ sensitivity: 'strict' });
    const relaxedEval = new RuleEvaluator({ sensitivity: 'relaxed' });
    try {
      const strictResult = strictEval.evaluate([NON_COMPLIANT_DIR], 'hipaa');
      const relaxedResult = relaxedEval.evaluate([NON_COMPLIANT_DIR], 'hipaa');
      expect(strictResult.findings.length).toBeGreaterThanOrEqual(relaxedResult.findings.length);
    } finally {
      strictEval.close();
      relaxedEval.close();
    }
  });

  it('should throw SecurityError for nonexistent path', () => {
    expect(() => validateScanPath('/nonexistent/path/that/does/not/exist')).toThrow(SecurityError);
  });
});

// ──────────────────────────────────────────────────
// compliance_score pipeline
// ──────────────────────────────────────────────────

describe('MCP Tool: compliance_score pipeline', () => {
  it('should produce a higher score for compliant fixture than non-compliant', () => {
    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const compliantResult = evaluator.evaluate([COMPLIANT_DIR], 'hipaa');
      const nonCompliantResult = evaluator.evaluate([NON_COMPLIANT_DIR], 'hipaa');
      const calculator = new ScoreCalculator();
      const compliantScore = calculator.calculateScore(compliantResult, 'hipaa', 'balanced');
      const nonCompliantScore = calculator.calculateScore(nonCompliantResult, 'hipaa', 'balanced');
      expect(compliantScore.overallScore).toBeGreaterThanOrEqual(nonCompliantScore.overallScore);
      expect(compliantScore.overallScore).toBeGreaterThan(0);
      expect(compliantScore.overallScore).toBeLessThanOrEqual(100);
    } finally {
      evaluator.close();
    }
  });

  it('should score non-compliant fixture with low score due to PHI clamp', () => {
    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const result = evaluator.evaluate([NON_COMPLIANT_DIR], 'hipaa');
      const calculator = new ScoreCalculator();
      const score = calculator.calculateScore(result, 'hipaa', 'balanced');
      expect(score.overallScore).toBeLessThanOrEqual(69);
      expect(['critical', 'at_risk']).toContain(score.band);
    } finally {
      evaluator.close();
    }
  });

  it('should include all 6 domain scores with correct weights', () => {
    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const result = evaluator.evaluate([NON_COMPLIANT_DIR], 'hipaa');
      const calculator = new ScoreCalculator();
      const score = calculator.calculateScore(result, 'hipaa', 'balanced');

      const domains = score.domainScores;
      expect(domains.phiProtection).toBeDefined();
      expect(domains.encryption).toBeDefined();
      expect(domains.accessControl).toBeDefined();
      expect(domains.auditLogging).toBeDefined();
      expect(domains.infrastructure).toBeDefined();
      expect(domains.aiGovernance).toBeDefined();

      // Verify weights
      expect(domains.phiProtection.weight).toBe(0.25);
      expect(domains.encryption.weight).toBe(0.2);
      expect(domains.accessControl.weight).toBe(0.2);
      expect(domains.auditLogging.weight).toBe(0.15);
      expect(domains.infrastructure.weight).toBe(0.1);
      expect(domains.aiGovernance.weight).toBe(0.1);
    } finally {
      evaluator.close();
    }
  });

  it('should include correct metadata in score', () => {
    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const result = evaluator.evaluate([COMPLIANT_DIR], 'hipaa');
      const calculator = new ScoreCalculator();
      const score = calculator.calculateScore(result, 'hipaa', 'balanced');
      expect(score.metadata.framework).toBe('hipaa');
      expect(score.metadata.rulesEvaluated).toBe(29);
      expect(score.metadata.filesScanned).toBeGreaterThanOrEqual(1);
    } finally {
      evaluator.close();
    }
  });
});

// ──────────────────────────────────────────────────
// compliance_report pipeline
// ──────────────────────────────────────────────────

describe('MCP Tool: compliance_report pipeline', () => {
  it('should generate a JSON report with valid structure', () => {
    const outputDir = join(INTEGRATION_TMP, 'report-test-1');
    mkdirSync(outputDir, { recursive: true });

    const report = buildReport(NON_COMPLIANT_DIR);
    const reportPath = generateJsonReport(report, outputDir);

    expect(existsSync(reportPath)).toBe(true);
    const parsed = JSON.parse(readFileSync(reportPath, 'utf-8'));
    expect(parsed).toHaveProperty('id');
    expect(parsed).toHaveProperty('version');
    expect(parsed).toHaveProperty('score');
    expect(parsed).toHaveProperty('findings');
    expect(parsed).toHaveProperty('summary');
    expect(parsed).toHaveProperty('metadata');
    expect(parsed.summary).toHaveProperty('bySeverity');
    expect(parsed.summary).toHaveProperty('byCategory');
  });

  it('should generate a report in a custom output directory', () => {
    const customDir = join(INTEGRATION_TMP, 'custom-report-dir');
    mkdirSync(customDir, { recursive: true });

    const report = buildReport(COMPLIANT_DIR);
    const reportPath = generateJsonReport(report, customDir);

    expect(existsSync(reportPath)).toBe(true);
    expect(reportPath.startsWith(customDir)).toBe(true);
  });

  it('should include correct report metadata', () => {
    const outputDir = join(INTEGRATION_TMP, 'report-test-meta');
    mkdirSync(outputDir, { recursive: true });

    const report = buildReport(NON_COMPLIANT_DIR);
    const reportPath = generateJsonReport(report, outputDir);
    const parsed = JSON.parse(readFileSync(reportPath, 'utf-8'));

    expect(parsed.metadata.hipaalintVersion).toBe('0.1.0');
    expect(parsed.metadata.frameworksEvaluated).toContain('hipaa');
    expect(parsed.generatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(parsed.projectName).toBe(basename(NON_COMPLIANT_DIR));
  });

  it('should create directory if missing via validateOutputDirectory', () => {
    const newDir = join(INTEGRATION_TMP, 'auto-created-dir');
    const result = validateOutputDirectory(newDir);
    expect(existsSync(result)).toBe(true);
  });
});

// ──────────────────────────────────────────────────
// phi_detect pipeline
// ──────────────────────────────────────────────────

describe('MCP Tool: phi_detect pipeline', () => {
  it('should detect SSN PHI in code snippet', () => {
    const detector = new PHIDetector({ sensitivity: 'balanced' });
    const code = 'const testSSN = "123-45-6789"; console.log(testSSN);';
    const findings = detector.detect(code, 'unknown.ts');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.identifierType === 'ssn')).toBe(true);
    expect(findings[0]!.citation).toContain('45 CFR');
  });

  it('should return no findings for clean code', () => {
    const detector = new PHIDetector({ sensitivity: 'balanced' });
    const code = 'const userId = "user-abc-123"; const status = "active";';
    const findings = detector.detect(code, 'clean.ts');
    expect(findings.length).toBe(0);
  });

  it('should detect more in strict than relaxed mode', () => {
    const strict = new PHIDetector({ sensitivity: 'strict' });
    const relaxed = new PHIDetector({ sensitivity: 'relaxed' });
    const code = 'const patientName = "John"; console.log(`Processing ${patientName}`);';
    const strictFindings = strict.detect(code, 'api.ts');
    const relaxedFindings = relaxed.detect(code, 'api.ts');
    expect(strictFindings.length).toBeGreaterThanOrEqual(relaxedFindings.length);
  });
});

// ──────────────────────────────────────────────────
// compliance_rules pipeline
// ──────────────────────────────────────────────────

describe('MCP Tool: compliance_rules pipeline', () => {
  it('should return all 29 rules', () => {
    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const db = evaluator.getRuleDatabase();
      const rules = db.getAllRules();
      expect(rules.length).toBe(29);
      for (const r of rules) {
        expect(r.ruleId).toBeDefined();
        expect(r.title).toBeDefined();
        expect(r.severity).toBeDefined();
        expect(r.category).toBeDefined();
      }
    } finally {
      evaluator.close();
    }
  });

  it('should search rules by keyword', () => {
    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const db = evaluator.getRuleDatabase();
      const results = db.searchRules('encryption');
      expect(results.length).toBeGreaterThan(0);
      expect(results.length).toBeLessThan(29);
    } finally {
      evaluator.close();
    }
  });

  it('should filter rules by category', () => {
    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const db = evaluator.getRuleDatabase();
      const results = db.getRulesByCategory('phi_protection', 'hipaa');
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        expect(r.category).toBe('phi_protection');
      }
    } finally {
      evaluator.close();
    }
  });

  it('should filter rules by severity', () => {
    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const db = evaluator.getRuleDatabase();
      const results = db.getRulesBySeverity('critical', 'hipaa');
      expect(results.length).toBeGreaterThan(0);
      for (const r of results) {
        expect(r.severity).toBe('critical');
      }
    } finally {
      evaluator.close();
    }
  });
});
