// ──────────────────────────────────────────────────
// Single-Pass Finding Counter
// ──────────────────────────────────────────────────

import type { ComplianceFinding, Severity, Category } from './types.js';

export interface FindingCounts {
  bySeverity: Record<Severity, number>;
  byCategory: Record<Category, number>;
  total: number;
}

/**
 * Count findings by severity and category in a single pass.
 * Replaces multiple `.filter().length` calls with one loop.
 */
export function countFindings(findings: ComplianceFinding[]): FindingCounts {
  const bySeverity: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const byCategory: Record<string, number> = {
    phi_protection: 0,
    encryption: 0,
    access_control: 0,
    audit_logging: 0,
    infrastructure: 0,
    ai_governance: 0,
  };

  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
  }

  return {
    bySeverity: bySeverity as Record<Severity, number>,
    byCategory: byCategory as Record<Category, number>,
    total: findings.length,
  };
}
