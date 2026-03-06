import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { generateJsonReport, generateSarifReport } from '../../src/reports/json-report.js';
import type { ComplianceReport } from '../../src/engine/types.js';
import { readFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const TEST_OUTPUT_DIR = join(tmpdir(), 'hipaalint-report-test');

function createMockReport(findingsCount = 1): ComplianceReport {
  const emptyDomain = {
    score: 100,
    weight: 0,
    totalCheckpoints: 0,
    passedCheckpoints: 0,
    failedCheckpoints: 0,
    warningCheckpoints: 0,
    findings: [],
  };

  const findings = Array.from({ length: findingsCount }, (_, i) => ({
    ruleId: `HIPAA-TEST-${String(i + 1).padStart(3, '0')}`,
    frameworkId: 'hipaa',
    severity: 'high' as const,
    category: 'phi_protection' as const,
    title: `Test Finding ${i + 1}`,
    description: `Test description ${i + 1}`,
    filePath: '/test/file.ts',
    lineNumber: i + 1,
    columnNumber: 1,
    codeSnippet: `const x${i} = "test";`,
    citation: '45 CFR test',
    remediation: 'Fix it',
    confidence: 'high' as const,
    timestamp: new Date().toISOString(),
  }));

  return {
    id: '00000000-0000-0000-0000-000000000000',
    version: '1.0.0',
    projectName: 'test-project',
    projectPath: '/test',
    generatedAt: '2026-01-15T00:00:00.000Z',
    score: {
      overallScore: 85,
      band: 'strong',
      domainScores: {
        phiProtection: emptyDomain,
        encryption: emptyDomain,
        accessControl: emptyDomain,
        auditLogging: emptyDomain,
        infrastructure: emptyDomain,
        aiGovernance: emptyDomain,
      },
      metadata: {
        scannedAt: '2026-01-15T00:00:00.000Z',
        filesScanned: 10,
        rulesEvaluated: 29,
        framework: 'hipaa',
        sensitivity: 'balanced',
        engineVersion: '1.0.0',
      },
    },
    findings,
    summary: {
      totalFindings: findingsCount,
      bySeverity: { critical: 0, high: findingsCount, medium: 0, low: 0, info: 0 },
      byCategory: {
        phi_protection: findingsCount,
        encryption: 0,
        access_control: 0,
        audit_logging: 0,
        infrastructure: 0,
        ai_governance: 0,
      },
    },
    recommendations: [],
    metadata: {
      hipaalintVersion: '1.0.0',
      rulesVersion: '1.0.0',
      frameworksEvaluated: ['hipaa'],
      sensitivity: 'balanced',
    },
  };
}

describe('JSON Report Generator', () => {
  beforeEach(() => {
    mkdirSync(TEST_OUTPUT_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_OUTPUT_DIR, { recursive: true, force: true });
  });

  describe('generateJsonReport', () => {
    it('should create JSON file at correct path', () => {
      const report = createMockReport();
      const outputPath = generateJsonReport(report, TEST_OUTPUT_DIR);
      expect(outputPath).toContain('hipaalint-report-2026-01-15.json');
      const content = readFileSync(outputPath, 'utf-8');
      expect(() => JSON.parse(content)).not.toThrow();
    });

    it('should include score data in output', () => {
      const report = createMockReport();
      const outputPath = generateJsonReport(report, TEST_OUTPUT_DIR);
      const content = JSON.parse(readFileSync(outputPath, 'utf-8'));
      expect(content.score.overallScore).toBe(85);
      expect(content.score.band).toBe('strong');
    });

    it('should flatten domain scores (no circular refs)', () => {
      const report = createMockReport();
      const outputPath = generateJsonReport(report, TEST_OUTPUT_DIR);
      const content = JSON.parse(readFileSync(outputPath, 'utf-8'));
      // Domain scores should have findingsCount instead of findings array
      expect(content.score.domainScores.phiProtection).toHaveProperty('findingsCount');
      expect(content.score.domainScores.phiProtection).not.toHaveProperty('findings');
    });

    it('should include disclaimer field', () => {
      const report = createMockReport();
      const outputPath = generateJsonReport(report, TEST_OUTPUT_DIR);
      const content = JSON.parse(readFileSync(outputPath, 'utf-8'));
      expect(content).toHaveProperty('disclaimer');
      expect(content.disclaimer).toContain('does not guarantee HIPAA compliance');
    });

    it('should handle empty findings', () => {
      const report = createMockReport(0);
      const outputPath = generateJsonReport(report, TEST_OUTPUT_DIR);
      const content = JSON.parse(readFileSync(outputPath, 'utf-8'));
      expect(content.findings).toHaveLength(0);
    });
  });

  describe('generateSarifReport', () => {
    it('should create valid SARIF structure', () => {
      const report = createMockReport(2);
      const outputPath = generateSarifReport(report, TEST_OUTPUT_DIR);
      const sarif = JSON.parse(readFileSync(outputPath, 'utf-8'));
      expect(sarif.version).toBe('2.1.0');
      expect(sarif).toHaveProperty('$schema');
      expect(sarif.runs).toHaveLength(1);
      expect(sarif.runs[0]).toHaveProperty('tool');
      expect(sarif.runs[0]).toHaveProperty('results');
    });

    it('should include all findings as results', () => {
      const report = createMockReport(3);
      const outputPath = generateSarifReport(report, TEST_OUTPUT_DIR);
      const sarif = JSON.parse(readFileSync(outputPath, 'utf-8'));
      expect(sarif.runs[0].results).toHaveLength(3);
    });

    it('should include disclaimer in SARIF properties', () => {
      const report = createMockReport(1);
      const outputPath = generateSarifReport(report, TEST_OUTPUT_DIR);
      const sarif = JSON.parse(readFileSync(outputPath, 'utf-8'));
      expect(sarif.runs[0]).toHaveProperty('properties');
      expect(sarif.runs[0].properties.disclaimer).toContain('does not guarantee HIPAA compliance');
    });

    it('should map high severity to error level', () => {
      const report = createMockReport(1);
      const outputPath = generateSarifReport(report, TEST_OUTPUT_DIR);
      const sarif = JSON.parse(readFileSync(outputPath, 'utf-8'));
      expect(sarif.runs[0].results[0].level).toBe('error');
    });
  });
});
