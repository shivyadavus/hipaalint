import type { ComplianceFinding } from './types.js';
import { readFileSync, writeFileSync } from 'fs';

// ──────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────

export interface FixResult {
  filePath: string;
  ruleId: string;
  lineNumber: number;
  originalLine: string;
  fixedLine: string;
  description: string;
}

export interface FixSummary {
  applied: FixResult[];
  skipped: Array<{
    ruleId: string;
    filePath: string;
    lineNumber: number;
    reason: string;
  }>;
  totalFixed: number;
  totalSkipped: number;
}

// ──────────────────────────────────────────────────
// Fixable rule IDs
// ──────────────────────────────────────────────────

const FIXABLE_RULES = new Set([
  'HIPAA-ENC-001', // Unencrypted HTTP → https://
  'HIPAA-ENC-005', // Weak TLS/SSL → TLSv1_2
  'HIPAA-INF-001', // CORS wildcard → env variable
]);

// ──────────────────────────────────────────────────
// Comment Detection
// ──────────────────────────────────────────────────

/**
 * Check if a line is a single-line comment.
 */
function isCommentLine(line: string): boolean {
  const trimmed = line.trimStart();
  return trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*');
}

/**
 * Build a map of which lines are inside block comments (/* ... *​/).
 * Returns a Set of 0-based line indices that are inside block comments.
 */
function computeBlockCommentLines(lines: string[]): Set<number> {
  const blockLines = new Set<number>();
  let inBlock = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    if (inBlock) {
      blockLines.add(i);
      if (line.includes('*/')) {
        inBlock = false;
      }
    } else {
      // Check for block comment start (but not single-line /* ... */ on same line)
      const startIdx = line.indexOf('/*');
      if (startIdx !== -1) {
        const endIdx = line.indexOf('*/', startIdx + 2);
        if (endIdx === -1) {
          // Block comment starts and does NOT close on this line
          blockLines.add(i);
          inBlock = true;
        } else {
          // Single-line block comment — still a comment line
          blockLines.add(i);
        }
      }
    }
  }

  return blockLines;
}

// ──────────────────────────────────────────────────
// AutoFixer
// ──────────────────────────────────────────────────

export class AutoFixer {
  /**
   * Apply auto-fixes for supported findings.
   * Groups by file for efficient I/O. Processes lines bottom-up
   * to preserve line numbers when multiple fixes target the same file.
   * Skips lines that are inside comments to avoid breaking code.
   */
  fix(findings: ComplianceFinding[], options: { dryRun?: boolean } = {}): FixSummary {
    const summary: FixSummary = {
      applied: [],
      skipped: [],
      totalFixed: 0,
      totalSkipped: 0,
    };

    // Group findings by file for batch I/O
    const byFile = new Map<string, ComplianceFinding[]>();
    for (const f of findings) {
      if (!FIXABLE_RULES.has(f.ruleId)) {
        summary.skipped.push({
          ruleId: f.ruleId,
          filePath: f.filePath,
          lineNumber: f.lineNumber,
          reason: 'No auto-fix available for this rule',
        });
        continue;
      }
      const existing = byFile.get(f.filePath) ?? [];
      existing.push(f);
      byFile.set(f.filePath, existing);
    }

    // Process each file
    for (const [filePath, fileFindings] of byFile) {
      try {
        const content = readFileSync(filePath, 'utf-8');
        const lines = content.split('\n');
        const blockCommentLines = computeBlockCommentLines(lines);
        let modified = false;

        // Sort by line number descending so fixes don't shift line indices
        const sorted = [...fileFindings].sort((a, b) => b.lineNumber - a.lineNumber);

        for (const finding of sorted) {
          const lineIdx = finding.lineNumber - 1;
          if (lineIdx < 0 || lineIdx >= lines.length) {
            summary.skipped.push({
              ruleId: finding.ruleId,
              filePath,
              lineNumber: finding.lineNumber,
              reason: 'Line number out of range',
            });
            continue;
          }

          const originalLine = lines[lineIdx]!;

          // Skip comment lines — modifying comments can break documentation or examples
          if (isCommentLine(originalLine) || blockCommentLines.has(lineIdx)) {
            summary.skipped.push({
              ruleId: finding.ruleId,
              filePath,
              lineNumber: finding.lineNumber,
              reason: 'Line is inside a comment',
            });
            continue;
          }

          const result = this.applyFix(finding, originalLine);

          if (result) {
            summary.applied.push({
              filePath,
              ruleId: finding.ruleId,
              lineNumber: finding.lineNumber,
              originalLine,
              fixedLine: result.fixedLine,
              description: result.description,
            });
            lines[lineIdx] = result.fixedLine;
            modified = true;
          } else {
            summary.skipped.push({
              ruleId: finding.ruleId,
              filePath,
              lineNumber: finding.lineNumber,
              reason: 'Fix could not be applied safely',
            });
          }
        }

        // Write back only if modified and not a dry run
        if (modified && !options.dryRun) {
          writeFileSync(filePath, lines.join('\n'), 'utf-8');
        }
      } catch {
        for (const f of fileFindings) {
          summary.skipped.push({
            ruleId: f.ruleId,
            filePath,
            lineNumber: f.lineNumber,
            reason: 'Could not read/write file',
          });
        }
      }
    }

    summary.totalFixed = summary.applied.length;
    summary.totalSkipped = summary.skipped.length;
    return summary;
  }

  /**
   * Attempt to apply a fix for a single finding on a single line.
   * Returns null if the fix cannot be applied safely.
   */
  private applyFix(
    finding: ComplianceFinding,
    line: string,
  ): { fixedLine: string; description: string } | null {
    switch (finding.ruleId) {
      case 'HIPAA-ENC-001':
        return this.fixUnencryptedHttp(line);
      case 'HIPAA-ENC-005':
        return this.fixWeakTLS(line);
      case 'HIPAA-INF-001':
        return this.fixCorsWildcard(line);
      default:
        return null;
    }
  }

  /**
   * HIPAA-ENC-001: Replace http:// with https://
   * Excludes localhost, 127.0.0.1, and 0.0.0.0 (safe for local dev).
   */
  private fixUnencryptedHttp(line: string): { fixedLine: string; description: string } | null {
    const fixedLine = line.replace(/http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/g, 'https://');
    if (fixedLine === line) return null;
    return {
      fixedLine,
      description: 'Upgraded http:// to https:// (verify target supports HTTPS)',
    };
  }

  /**
   * HIPAA-ENC-005: Replace weak TLS/SSL versions with TLSv1_2.
   * Handles TLSv1_0, TLSv1_1, SSLv3, ssl3, tls1_0, tls1_1.
   */
  private fixWeakTLS(line: string): { fixedLine: string; description: string } | null {
    const fixedLine = line.replace(/\b(TLSv1_0|TLSv1_1|SSLv3|ssl3|tls1_0|tls1_1)\b/g, (match) => {
      // Preserve casing convention
      if (/^[A-Z]/.test(match)) return 'TLSv1_2';
      return 'tls1_2';
    });
    if (fixedLine === line) return null;
    return { fixedLine, description: 'Upgraded weak TLS/SSL version to TLSv1_2' };
  }

  /**
   * HIPAA-INF-001: Replace CORS wildcard with environment variable reference.
   * Handles three patterns:
   *   1. origin: "*"  →  origin: process.env.CORS_ORIGIN
   *   2. Access-Control-Allow-Origin: "*"  →  process.env.CORS_ORIGIN
   *   3. cors()  →  cors({ origin: process.env.CORS_ORIGIN })
   */
  private fixCorsWildcard(line: string): { fixedLine: string; description: string } | null {
    // Pattern 1: origin: "*" or origin: '*'
    const originWildcard = /origin:\s*["'`]\*["'`]/;
    if (originWildcard.test(line)) {
      const fixedLine = line.replace(originWildcard, 'origin: process.env.CORS_ORIGIN');
      return { fixedLine, description: 'Replaced CORS wildcard origin with environment variable' };
    }

    // Pattern 2: Access-Control-Allow-Origin header with wildcard
    const headerWildcard = /(Access-Control-Allow-Origin['"]*\s*[:,]\s*)["'`]\*["'`]/;
    if (headerWildcard.test(line)) {
      const fixedLine = line.replace(headerWildcard, '$1process.env.CORS_ORIGIN');
      return {
        fixedLine,
        description: 'Replaced CORS wildcard header with environment variable',
      };
    }

    // Pattern 3: cors() with no arguments → add origin config
    const corsNoArgs = /\bcors\(\s*\)/;
    if (corsNoArgs.test(line)) {
      const fixedLine = line.replace(corsNoArgs, 'cors({ origin: process.env.CORS_ORIGIN })');
      return { fixedLine, description: 'Added CORS origin restriction' };
    }

    return null;
  }
}

/**
 * Returns the set of rule IDs that support auto-fixing.
 */
export function getFixableRuleIds(): ReadonlySet<string> {
  return FIXABLE_RULES;
}
