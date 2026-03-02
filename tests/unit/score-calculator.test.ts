import { describe, it, expect } from 'vitest';
import { ScoreCalculator } from '../../src/engine/score-calculator.js';
import type { ScanResult, ComplianceFinding } from '../../src/engine/types.js';

function createFinding(overrides: Partial<ComplianceFinding> = {}): ComplianceFinding {
    return {
        ruleId: 'HIPAA-TEST-001',
        frameworkId: 'hipaa',
        severity: 'medium',
        category: 'phi_protection',
        title: 'Test Finding',
        description: 'A test finding',
        filePath: '/test/file.ts',
        lineNumber: 1,
        columnNumber: 1,
        codeSnippet: 'test code',
        citation: '45 CFR §164.502',
        remediation: 'Fix this',
        confidence: 'high',
        timestamp: new Date().toISOString(),
        ...overrides,
    };
}

function createScanResult(findings: ComplianceFinding[] = []): ScanResult {
    return {
        findings,
        filesScanned: 10,
        filesSkipped: 0,
        rulesEvaluated: 29,
        scanDurationMs: 100,
        timestamp: new Date().toISOString(),
    };
}

describe('ScoreCalculator', () => {
    const calculator = new ScoreCalculator();

    describe('calculateScore', () => {
        it('should return 100 for no findings', () => {
            const result = createScanResult([]);
            const score = calculator.calculateScore(result);
            expect(score.overallScore).toBe(100);
            expect(score.band).toBe('compliant');
        });

        it('should penalize critical findings heavily', () => {
            const result = createScanResult([
                createFinding({ severity: 'critical', category: 'phi_protection' }),
            ]);
            const score = calculator.calculateScore(result);
            expect(score.overallScore).toBeLessThan(100);
        });

        it('should penalize high findings moderately', () => {
            const result = createScanResult([
                createFinding({ severity: 'high', category: 'encryption' }),
            ]);
            const score = calculator.calculateScore(result);
            expect(score.overallScore).toBeLessThan(100);
            expect(score.overallScore).toBeGreaterThan(50);
        });

        it('should clamp score to 69 for critical PHI finding', () => {
            const result = createScanResult([
                createFinding({ severity: 'critical', category: 'phi_protection' }),
            ]);
            const score = calculator.calculateScore(result);
            expect(score.overallScore).toBeLessThanOrEqual(69);
        });

        it('should assign correct bands', () => {
            // No findings → compliant
            let score = calculator.calculateScore(createScanResult([]));
            expect(score.band).toBe('compliant');

            // Many findings → lower band
            const manyFindings = Array(20).fill(null).map(() =>
                createFinding({ severity: 'high', category: 'encryption' }),
            );
            score = calculator.calculateScore(createScanResult(manyFindings));
            expect(['needs_improvement', 'at_risk', 'critical']).toContain(score.band);
        });

        it('should include all 6 domain scores', () => {
            const result = createScanResult([]);
            const score = calculator.calculateScore(result);
            expect(score.domainScores).toHaveProperty('phiProtection');
            expect(score.domainScores).toHaveProperty('encryption');
            expect(score.domainScores).toHaveProperty('accessControl');
            expect(score.domainScores).toHaveProperty('auditLogging');
            expect(score.domainScores).toHaveProperty('infrastructure');
            expect(score.domainScores).toHaveProperty('aiGovernance');
        });

        it('should include correct metadata', () => {
            const result = createScanResult([]);
            const score = calculator.calculateScore(result, 'hipaa', 'balanced');
            expect(score.metadata.framework).toBe('hipaa');
            expect(score.metadata.sensitivity).toBe('balanced');
            expect(score.metadata.filesScanned).toBe(10);
            expect(score.metadata.rulesEvaluated).toBe(29);
        });

        it('should group findings into correct domains', () => {
            const result = createScanResult([
                createFinding({ category: 'phi_protection' }),
                createFinding({ category: 'encryption' }),
                createFinding({ category: 'access_control' }),
            ]);
            const score = calculator.calculateScore(result);

            expect(score.domainScores.phiProtection.findings.length).toBe(1);
            expect(score.domainScores.encryption.findings.length).toBe(1);
            expect(score.domainScores.accessControl.findings.length).toBe(1);
        });

        it('should weight domains correctly', () => {
            const result = createScanResult([]);
            const score = calculator.calculateScore(result);

            expect(score.domainScores.phiProtection.weight).toBe(0.25);
            expect(score.domainScores.encryption.weight).toBe(0.20);
            expect(score.domainScores.accessControl.weight).toBe(0.20);
            expect(score.domainScores.auditLogging.weight).toBe(0.15);
            expect(score.domainScores.infrastructure.weight).toBe(0.10);
            expect(score.domainScores.aiGovernance.weight).toBe(0.10);
        });
    });
});
