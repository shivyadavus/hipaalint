import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { generatePdfReport } from '../../src/reports/pdf-report.js';
import type { ComplianceReport } from '../../src/engine/types.js';
import { existsSync, mkdirSync, rmSync, statSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const TEST_OUTPUT_DIR = join(tmpdir(), 'hipaalint-pdf-test');

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
    severity: (i === 0 ? 'critical' : i === 1 ? 'high' : 'medium') as
      | 'critical'
      | 'high'
      | 'medium',
    category: 'phi_protection' as const,
    title: `Test Finding ${i + 1}`,
    description: `Test description ${i + 1}`,
    filePath: '/test/project/src/file.ts',
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
    projectPath: '/test/project',
    generatedAt: '2026-01-15T00:00:00.000Z',
    score: {
      overallScore: 65,
      band: 'at_risk',
      domainScores: {
        phiProtection: { ...emptyDomain, score: 40, weight: 0.25, findings },
        encryption: { ...emptyDomain, weight: 0.2 },
        accessControl: { ...emptyDomain, weight: 0.2 },
        auditLogging: { ...emptyDomain, weight: 0.15 },
        infrastructure: { ...emptyDomain, weight: 0.1 },
        aiGovernance: { ...emptyDomain, weight: 0.1 },
      },
      metadata: {
        scannedAt: '2026-01-15T00:00:00.000Z',
        filesScanned: 10,
        rulesEvaluated: 33,
        framework: 'hipaa',
        sensitivity: 'balanced',
        engineVersion: '1.0.0',
      },
    },
    findings,
    summary: {
      totalFindings: findingsCount,
      bySeverity: {
        critical: findingsCount > 0 ? 1 : 0,
        high: findingsCount > 1 ? 1 : 0,
        medium: findingsCount > 2 ? findingsCount - 2 : 0,
        low: 0,
        info: 0,
      },
      byCategory: {
        phi_protection: findingsCount,
        encryption: 0,
        access_control: 0,
        audit_logging: 0,
        infrastructure: 0,
        ai_governance: 0,
      },
    },
    recommendations: [
      {
        priority: 1,
        description: 'Fix critical PHI exposure in source code.',
        affectedRules: ['HIPAA-TEST-001'],
      },
    ],
    metadata: {
      hipaalintVersion: '1.0.0',
      rulesVersion: '1.0.0',
      frameworksEvaluated: ['hipaa'],
      sensitivity: 'balanced',
    },
  };
}

describe('PDF Report Generator', () => {
  beforeEach(() => {
    mkdirSync(TEST_OUTPUT_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_OUTPUT_DIR, { recursive: true, force: true });
  });

  it('should create a PDF file at correct path', async () => {
    const report = createMockReport(3);
    const outputPath = await generatePdfReport(report, TEST_OUTPUT_DIR);
    expect(outputPath).toContain('hipaalint-report-2026-01-15.pdf');
    expect(existsSync(outputPath)).toBe(true);
  });

  it('should produce a non-empty PDF file', async () => {
    const report = createMockReport(3);
    const outputPath = await generatePdfReport(report, TEST_OUTPUT_DIR);
    const stat = statSync(outputPath);
    expect(stat.size).toBeGreaterThan(0);
  });

  it('should handle report with zero findings', async () => {
    const report = createMockReport(0);
    const outputPath = await generatePdfReport(report, TEST_OUTPUT_DIR);
    expect(existsSync(outputPath)).toBe(true);
    const stat = statSync(outputPath);
    expect(stat.size).toBeGreaterThan(0);
  });

  it('should handle report with many findings (truncation)', async () => {
    const report = createMockReport(30);
    const outputPath = await generatePdfReport(report, TEST_OUTPUT_DIR);
    expect(existsSync(outputPath)).toBe(true);
    const stat = statSync(outputPath);
    // PDF with many findings should still be reasonable size
    expect(stat.size).toBeGreaterThan(1000);
  });

  it('should handle report with recommendations', async () => {
    const report = createMockReport(2);
    report.recommendations = Array.from({ length: 5 }, (_, i) => ({
      priority: i + 1,
      description: `Recommendation ${i + 1}: Fix finding.`,
      affectedRules: [`HIPAA-TEST-${String(i + 1).padStart(3, '0')}`],
    }));
    const outputPath = await generatePdfReport(report, TEST_OUTPUT_DIR);
    expect(existsSync(outputPath)).toBe(true);
  });

  it('should include correct date in filename', async () => {
    const report = createMockReport(1);
    const outputPath = await generatePdfReport(report, TEST_OUTPUT_DIR);
    expect(outputPath).toContain('2026-01-15');
  });

  it('should produce valid PDF header (magic bytes)', async () => {
    const report = createMockReport(1);
    const outputPath = await generatePdfReport(report, TEST_OUTPUT_DIR);
    const { readFileSync } = await import('fs');
    const buffer = readFileSync(outputPath);
    // PDF files start with %PDF-
    const header = buffer.subarray(0, 5).toString('ascii');
    expect(header).toBe('%PDF-');
  });
});
