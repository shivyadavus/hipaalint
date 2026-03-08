import { describe, it, expect } from 'vitest';
import { countFindings } from '../../src/engine/finding-counter.js';
import type { ComplianceFinding } from '../../src/engine/types.js';

function mockFinding(
  severity: 'critical' | 'high' | 'medium' | 'low',
  category: 'phi_protection' | 'encryption' | 'access_control',
): ComplianceFinding {
  return {
    ruleId: 'TEST-001',
    frameworkId: 'hipaa',
    severity,
    category,
    title: 'Test',
    description: 'Test',
    filePath: '/test.ts',
    lineNumber: 1,
    columnNumber: 1,
    codeSnippet: 'test',
    citation: '45 CFR test',
    remediation: 'Fix it',
    confidence: 'high',
    timestamp: new Date().toISOString(),
  };
}

describe('countFindings', () => {
  it('should return zero counts for empty array', () => {
    const result = countFindings([]);
    expect(result.total).toBe(0);
    expect(result.bySeverity.critical).toBe(0);
    expect(result.bySeverity.high).toBe(0);
    expect(result.byCategory.phi_protection).toBe(0);
  });

  it('should count findings by severity', () => {
    const findings = [
      mockFinding('critical', 'phi_protection'),
      mockFinding('critical', 'encryption'),
      mockFinding('high', 'access_control'),
      mockFinding('medium', 'phi_protection'),
    ];
    const result = countFindings(findings);
    expect(result.total).toBe(4);
    expect(result.bySeverity.critical).toBe(2);
    expect(result.bySeverity.high).toBe(1);
    expect(result.bySeverity.medium).toBe(1);
    expect(result.bySeverity.low).toBe(0);
  });

  it('should count findings by category', () => {
    const findings = [
      mockFinding('critical', 'phi_protection'),
      mockFinding('high', 'phi_protection'),
      mockFinding('high', 'encryption'),
    ];
    const result = countFindings(findings);
    expect(result.byCategory.phi_protection).toBe(2);
    expect(result.byCategory.encryption).toBe(1);
    expect(result.byCategory.access_control).toBe(0);
  });
});
