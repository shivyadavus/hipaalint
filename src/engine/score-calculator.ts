import type {
  ComplianceFinding,
  ComplianceScore,
  DomainScore,
  ScanResult,
  ScoreBand,
  Category,
  SensitivityLevel,
} from './types.js';
import { DOMAIN_WEIGHTS, SCORE_BAND_THRESHOLDS, SCORE_CLAMP_RULES } from './types.js';
import { VERSION } from '../version.js';

// ──────────────────────────────────────────────────
// Category → Domain mapping
// ──────────────────────────────────────────────────

const CATEGORY_TO_DOMAIN: Record<Category, keyof ComplianceScore['domainScores']> = {
  phi_protection: 'phiProtection',
  encryption: 'encryption',
  access_control: 'accessControl',
  audit_logging: 'auditLogging',
  infrastructure: 'infrastructure',
  ai_governance: 'aiGovernance',
};

// ──────────────────────────────────────────────────
// Clamping rule matchers (category + title-based, no hardcoded IDs)
// ──────────────────────────────────────────────────

const ENCRYPTION_AT_REST_KEYWORDS = ['encryption at rest', 'encryption and decryption'];
const MFA_KEYWORDS = ['mfa', 'multi-factor', 'two-factor', 'multifactor'];

// ──────────────────────────────────────────────────
// Score Calculator
// ──────────────────────────────────────────────────

export class ScoreCalculator {
  /**
   * Calculate the HipaaLint Score from scan results.
   */
  calculateScore(
    scanResult: ScanResult,
    framework = 'hipaa',
    sensitivity: SensitivityLevel = 'balanced',
  ): ComplianceScore {
    // Group findings by domain
    const domainFindings = this.groupByDomain(scanResult.findings);

    // Calculate domain scores
    const domainScores = this.calculateDomainScores(domainFindings, scanResult.rulesEvaluated);

    // Calculate weighted overall score
    let overallScore = this.calculateWeightedScore(domainScores);

    // Apply clamping rules
    overallScore = this.applyClampRules(overallScore, scanResult.findings);

    // Empty project guard: if no files were scanned, score is not meaningful
    if (scanResult.filesScanned === 0) {
      overallScore = 0;
    }

    // Determine band
    const band =
      scanResult.filesScanned === 0 ? ('critical' as ScoreBand) : this.determineBand(overallScore);

    return {
      overallScore: Math.round(overallScore * 10) / 10,
      band,
      domainScores,
      metadata: {
        scannedAt: scanResult.timestamp,
        filesScanned: scanResult.filesScanned,
        rulesEvaluated: scanResult.rulesEvaluated,
        framework,
        sensitivity,
        engineVersion: VERSION,
      },
    };
  }

  /**
   * Group findings by compliance domain.
   */
  private groupByDomain(
    findings: ComplianceFinding[],
  ): Record<keyof ComplianceScore['domainScores'], ComplianceFinding[]> {
    const grouped: Record<keyof ComplianceScore['domainScores'], ComplianceFinding[]> = {
      phiProtection: [],
      encryption: [],
      accessControl: [],
      auditLogging: [],
      infrastructure: [],
      aiGovernance: [],
    };

    for (const finding of findings) {
      const domain = CATEGORY_TO_DOMAIN[finding.category];
      if (domain) {
        grouped[domain].push(finding);
      }
    }

    return grouped;
  }

  /**
   * Calculate scores for each domain.
   */
  private calculateDomainScores(
    domainFindings: Record<keyof ComplianceScore['domainScores'], ComplianceFinding[]>,
    totalRulesEvaluated: number,
  ): ComplianceScore['domainScores'] {
    const domainKeys = Object.keys(domainFindings) as Array<keyof ComplianceScore['domainScores']>;
    const rulesPerDomain = Math.max(1, Math.ceil(totalRulesEvaluated / domainKeys.length));

    const scores: Record<string, DomainScore> = {};

    for (const domain of domainKeys) {
      const findings = domainFindings[domain];
      scores[domain] = this.calculateSingleDomainScore(
        findings,
        rulesPerDomain,
        DOMAIN_WEIGHTS[domain],
      );
    }

    return scores as ComplianceScore['domainScores'];
  }

  /**
   * Calculate score for a single domain.
   */
  private calculateSingleDomainScore(
    findings: ComplianceFinding[],
    totalCheckpoints: number,
    weight: number,
  ): DomainScore {
    // Count findings by severity (single-pass)
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    for (const f of findings) {
      switch (f.severity) {
        case 'critical':
          critical++;
          break;
        case 'high':
          high++;
          break;
        case 'medium':
          medium++;
          break;
        case 'low':
          low++;
          break;
      }
    }

    // Weighted penalties: critical findings count more than low
    const penaltyScore =
      critical * 15 + // critical findings heavily penalize
      high * 8 +
      medium * 3 +
      low * 1;

    // Calculate score (0-100)
    const maxPenalty = totalCheckpoints * 15; // worst case: all critical
    const rawScore = Math.max(0, 100 - (penaltyScore / Math.max(1, maxPenalty)) * 100);

    // If no rules evaluated for this domain, assume compliant but with warning
    const score = totalCheckpoints === 0 ? 100 : Math.round(rawScore * 10) / 10;

    const failedCheckpoints = critical + high;
    const warningCheckpoints = medium + low;
    const passedCheckpoints = Math.max(
      0,
      totalCheckpoints - failedCheckpoints - warningCheckpoints,
    );

    return {
      score,
      weight,
      totalCheckpoints,
      passedCheckpoints,
      failedCheckpoints,
      warningCheckpoints,
      findings,
    };
  }

  /**
   * Calculate weighted overall score from domain scores.
   */
  private calculateWeightedScore(domainScores: ComplianceScore['domainScores']): number {
    let weightedSum = 0;
    let totalWeight = 0;

    for (const [domain, score] of Object.entries(domainScores)) {
      const weight = DOMAIN_WEIGHTS[domain as keyof ComplianceScore['domainScores']];
      weightedSum += score.score * weight;
      totalWeight += weight;
    }

    return totalWeight > 0 ? weightedSum / totalWeight : 100;
  }

  /**
   * Apply score clamping rules per PRD Section 6.
   * Uses category + keyword matching instead of hardcoded rule IDs for resilience.
   * Graduated clamping: more critical findings produce a lower cap.
   */
  private applyClampRules(score: number, findings: ComplianceFinding[]): number {
    let clampedScore = score;

    // Count critical PHI findings for graduated clamping
    const criticalPHICount = findings.filter(
      (f) => f.category === 'phi_protection' && f.severity === 'critical',
    ).length;

    if (criticalPHICount >= 6) {
      clampedScore = Math.min(clampedScore, SCORE_CLAMP_RULES.manyCriticalPHI); // 6+ → max 49
    } else if (criticalPHICount >= 2) {
      clampedScore = Math.min(clampedScore, SCORE_CLAMP_RULES.multipleCriticalPHI); // 2-5 → max 59
    } else if (criticalPHICount >= 1) {
      clampedScore = Math.min(clampedScore, SCORE_CLAMP_RULES.criticalPHIFinding); // 1 → max 69
    }

    // No encryption at rest → capped at 59 (match by category + title keywords)
    const hasNoEncryption = findings.some(
      (f) =>
        f.category === 'encryption' &&
        f.severity === 'critical' &&
        ENCRYPTION_AT_REST_KEYWORDS.some((kw) => f.title.toLowerCase().includes(kw)),
    );
    if (hasNoEncryption) {
      clampedScore = Math.min(clampedScore, SCORE_CLAMP_RULES.noEncryptionAtRest);
    }

    // No MFA enforcement → capped at 79 (match by category + title keywords)
    const hasMFAFinding = findings.some(
      (f) =>
        f.category === 'access_control' &&
        MFA_KEYWORDS.some((kw) => f.title.toLowerCase().includes(kw)),
    );
    if (hasMFAFinding) {
      clampedScore = Math.min(clampedScore, SCORE_CLAMP_RULES.noMFAEnforcement);
    }

    return clampedScore;
  }

  /**
   * Determine score band from overall score.
   */
  private determineBand(score: number): ScoreBand {
    if (score >= SCORE_BAND_THRESHOLDS.strong) return 'strong';
    if (score >= SCORE_BAND_THRESHOLDS.needs_improvement) return 'needs_improvement';
    if (score >= SCORE_BAND_THRESHOLDS.at_risk) return 'at_risk';
    return 'critical';
  }
}
