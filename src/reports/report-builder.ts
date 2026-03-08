import type { ComplianceFinding, ComplianceReport, SensitivityLevel } from '../engine/types.js';
import type { ScanResult, ComplianceScore } from '../engine/types.js';
import { countFindings } from '../engine/finding-counter.js';
import { VERSION, RULES_VERSION } from '../version.js';
import { randomUUID } from 'crypto';
import { basename } from 'path';

/**
 * Build a ComplianceReport from scan results and score.
 */
export function buildReport(
    scanResult: ScanResult,
    score: ComplianceScore,
    projectPath: string,
    framework: string,
    sensitivity: SensitivityLevel,
): ComplianceReport {
    const counts = countFindings(scanResult.findings);

    return {
        id: randomUUID(),
        version: VERSION,
        projectName: basename(projectPath),
        projectPath,
        generatedAt: new Date().toISOString(),
        score,
        findings: scanResult.findings,
        summary: {
            totalFindings: counts.total,
            bySeverity: counts.bySeverity,
            byCategory: counts.byCategory,
        },
        recommendations: generateRecommendations(scanResult.findings),
        metadata: {
            hipaalintVersion: VERSION,
            rulesVersion: RULES_VERSION,
            frameworksEvaluated: [framework],
            sensitivity,
        },
    };
}

/**
 * Generate prioritized recommendations from findings.
 */
export function generateRecommendations(
    findings: ComplianceFinding[],
): ComplianceReport['recommendations'] {
    const recs: ComplianceReport['recommendations'] = [];

    // Group by rule — highest severity first
    const byRule = new Map<string, ComplianceFinding[]>();
    for (const f of findings) {
        const existing = byRule.get(f.ruleId) || [];
        existing.push(f);
        byRule.set(f.ruleId, existing);
    }

    const severityOrder = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
    const sorted = [...byRule.entries()].sort((a, b) => {
        const aMax = Math.min(...a[1].map((f) => severityOrder[f.severity]));
        const bMax = Math.min(...b[1].map((f) => severityOrder[f.severity]));
        return aMax - bMax;
    });

    let priority = 1;
    for (const [ruleId, ruleFindings] of sorted) {
        recs.push({
            priority,
            description: `Fix ${ruleFindings.length} ${ruleFindings[0]!.severity} finding(s): ${ruleFindings[0]!.title}. ${ruleFindings[0]!.remediation}`,
            affectedRules: [ruleId],
        });
        priority++;
    }

    return recs;
}
