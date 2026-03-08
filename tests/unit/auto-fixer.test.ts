import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AutoFixer, getFixableRuleIds } from '../../src/engine/auto-fixer.js';
import type { ComplianceFinding } from '../../src/engine/types.js';
import { writeFileSync, readFileSync, mkdirSync, rmSync } from 'fs';
import { join, resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = resolve(__dirname, '../fixtures/auto-fix-temp');

function createFinding(
  overrides: Partial<ComplianceFinding> &
    Pick<ComplianceFinding, 'ruleId' | 'filePath' | 'lineNumber'>,
): ComplianceFinding {
  return {
    ruleId: overrides.ruleId,
    frameworkId: 'hipaa',
    severity: overrides.severity ?? 'high',
    category: overrides.category ?? 'encryption',
    title: overrides.title ?? 'Test Finding',
    description: overrides.description ?? 'Test',
    filePath: overrides.filePath,
    lineNumber: overrides.lineNumber,
    columnNumber: overrides.columnNumber ?? 1,
    codeSnippet: overrides.codeSnippet ?? '',
    citation: overrides.citation ?? '45 CFR §164',
    remediation: overrides.remediation ?? 'Fix it',
    confidence: overrides.confidence ?? 'high',
    timestamp: new Date().toISOString(),
  };
}

describe('AutoFixer', () => {
  let fixer: AutoFixer;

  beforeEach(() => {
    fixer = new AutoFixer();
    mkdirSync(FIXTURE_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(FIXTURE_DIR, { recursive: true, force: true });
  });

  // ── getFixableRuleIds ──

  describe('getFixableRuleIds', () => {
    it('returns a set of fixable rule IDs', () => {
      const ids = getFixableRuleIds();
      expect(ids).toBeInstanceOf(Set);
      expect(ids.has('HIPAA-ENC-001')).toBe(true);
      expect(ids.has('HIPAA-ENC-005')).toBe(true);
      expect(ids.has('HIPAA-INF-001')).toBe(true);
    });

    it('does not include non-fixable rules', () => {
      const ids = getFixableRuleIds();
      expect(ids.has('HIPAA-PHI-001')).toBe(false);
      expect(ids.has('HIPAA-AC-001')).toBe(false);
    });
  });

  // ── HIPAA-ENC-001: Unencrypted HTTP ──

  describe('HIPAA-ENC-001 — Unencrypted HTTP', () => {
    it('replaces http:// with https://', () => {
      const filePath = join(FIXTURE_DIR, 'http-test.ts');
      writeFileSync(filePath, 'const url = "http://api.example.com/data";\n');

      const findings = [createFinding({ ruleId: 'HIPAA-ENC-001', filePath, lineNumber: 1 })];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(1);
      expect(result.applied[0]!.description).toContain('Upgraded http:// to https://');

      const content = readFileSync(filePath, 'utf-8');
      expect(content).toBe('const url = "https://api.example.com/data";\n');
    });

    it('preserves localhost URLs', () => {
      const filePath = join(FIXTURE_DIR, 'localhost-test.ts');
      writeFileSync(filePath, 'const url = "http://localhost:3000/api";\n');

      const findings = [createFinding({ ruleId: 'HIPAA-ENC-001', filePath, lineNumber: 1 })];

      const result = fixer.fix(findings);
      // Cannot fix — the line already has a safe URL
      expect(result.totalFixed).toBe(0);
      expect(result.skipped.some((s) => s.reason === 'Fix could not be applied safely')).toBe(true);
    });

    it('preserves 127.0.0.1 URLs', () => {
      const filePath = join(FIXTURE_DIR, 'loopback-test.ts');
      writeFileSync(filePath, 'const url = "http://127.0.0.1:8080";\n');

      const findings = [createFinding({ ruleId: 'HIPAA-ENC-001', filePath, lineNumber: 1 })];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(0);
    });

    it('fixes multiple http:// URLs on the same line', () => {
      const filePath = join(FIXTURE_DIR, 'multi-http.ts');
      writeFileSync(filePath, 'const urls = ["http://a.com", "http://b.com"];\n');

      const findings = [createFinding({ ruleId: 'HIPAA-ENC-001', filePath, lineNumber: 1 })];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(1);

      const content = readFileSync(filePath, 'utf-8');
      expect(content).toBe('const urls = ["https://a.com", "https://b.com"];\n');
    });
  });

  // ── HIPAA-ENC-005: Weak TLS ──

  describe('HIPAA-ENC-005 — Weak TLS Versions', () => {
    it('replaces TLSv1_0 with TLSv1_2', () => {
      const filePath = join(FIXTURE_DIR, 'tls-test.ts');
      writeFileSync(filePath, 'const version = "TLSv1_0";\n');

      const findings = [createFinding({ ruleId: 'HIPAA-ENC-005', filePath, lineNumber: 1 })];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(1);

      const content = readFileSync(filePath, 'utf-8');
      expect(content).toBe('const version = "TLSv1_2";\n');
    });

    it('replaces SSLv3 with TLSv1_2', () => {
      const filePath = join(FIXTURE_DIR, 'ssl-test.ts');
      writeFileSync(filePath, 'const proto = SSLv3;\n');

      const findings = [createFinding({ ruleId: 'HIPAA-ENC-005', filePath, lineNumber: 1 })];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(1);

      const content = readFileSync(filePath, 'utf-8');
      expect(content).toBe('const proto = TLSv1_2;\n');
    });

    it('replaces lowercase tls1_0 with tls1_2', () => {
      const filePath = join(FIXTURE_DIR, 'tls-lower.ts');
      writeFileSync(filePath, 'const v = tls1_0;\n');

      const findings = [createFinding({ ruleId: 'HIPAA-ENC-005', filePath, lineNumber: 1 })];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(1);

      const content = readFileSync(filePath, 'utf-8');
      expect(content).toBe('const v = tls1_2;\n');
    });

    it('replaces TLSv1_1 with TLSv1_2', () => {
      const filePath = join(FIXTURE_DIR, 'tls11-test.ts');
      writeFileSync(filePath, 'minVersion: "TLSv1_1",\n');

      const findings = [createFinding({ ruleId: 'HIPAA-ENC-005', filePath, lineNumber: 1 })];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(1);

      const content = readFileSync(filePath, 'utf-8');
      expect(content).toContain('TLSv1_2');
    });
  });

  // ── HIPAA-INF-001: CORS Wildcard ──

  describe('HIPAA-INF-001 — CORS Wildcard', () => {
    it('replaces origin: "*" with environment variable', () => {
      const filePath = join(FIXTURE_DIR, 'cors-test.ts');
      writeFileSync(filePath, 'const config = { origin: "*" };\n');

      const findings = [
        createFinding({
          ruleId: 'HIPAA-INF-001',
          filePath,
          lineNumber: 1,
          category: 'infrastructure',
        }),
      ];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(1);

      const content = readFileSync(filePath, 'utf-8');
      expect(content).toContain('process.env.CORS_ORIGIN');
      expect(content).not.toContain('"*"');
    });

    it("replaces origin: '*' (single quotes)", () => {
      const filePath = join(FIXTURE_DIR, 'cors-single.ts');
      writeFileSync(filePath, "const config = { origin: '*' };\n");

      const findings = [
        createFinding({
          ruleId: 'HIPAA-INF-001',
          filePath,
          lineNumber: 1,
          category: 'infrastructure',
        }),
      ];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(1);

      const content = readFileSync(filePath, 'utf-8');
      expect(content).toContain('process.env.CORS_ORIGIN');
    });

    it('replaces cors() with cors({ origin: ... })', () => {
      const filePath = join(FIXTURE_DIR, 'cors-empty.ts');
      writeFileSync(filePath, 'app.use(cors());\n');

      const findings = [
        createFinding({
          ruleId: 'HIPAA-INF-001',
          filePath,
          lineNumber: 1,
          category: 'infrastructure',
        }),
      ];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(1);

      const content = readFileSync(filePath, 'utf-8');
      expect(content).toContain('cors({ origin: process.env.CORS_ORIGIN })');
    });
  });

  // ── Dry Run ──

  describe('dry-run mode', () => {
    it('reports fixes but does not modify files', () => {
      const filePath = join(FIXTURE_DIR, 'dry-run.ts');
      const original = 'const url = "http://api.example.com";\n';
      writeFileSync(filePath, original);

      const findings = [createFinding({ ruleId: 'HIPAA-ENC-001', filePath, lineNumber: 1 })];

      const result = fixer.fix(findings, { dryRun: true });
      expect(result.totalFixed).toBe(1);
      expect(result.applied[0]!.fixedLine).toContain('https://');

      // File should NOT be modified
      const content = readFileSync(filePath, 'utf-8');
      expect(content).toBe(original);
    });
  });

  // ── Multi-line & Multi-file ──

  describe('multi-finding scenarios', () => {
    it('fixes multiple findings in the same file', () => {
      const filePath = join(FIXTURE_DIR, 'multi.ts');
      const lines = [
        'const api = "http://api.example.com";',
        'const version = TLSv1_0;',
        'const cors = { origin: "*" };',
        '',
      ];
      writeFileSync(filePath, lines.join('\n'));

      const findings = [
        createFinding({ ruleId: 'HIPAA-ENC-001', filePath, lineNumber: 1 }),
        createFinding({ ruleId: 'HIPAA-ENC-005', filePath, lineNumber: 2 }),
        createFinding({
          ruleId: 'HIPAA-INF-001',
          filePath,
          lineNumber: 3,
          category: 'infrastructure',
        }),
      ];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(3);

      const content = readFileSync(filePath, 'utf-8');
      expect(content).toContain('https://');
      expect(content).toContain('TLSv1_2');
      expect(content).toContain('process.env.CORS_ORIGIN');
    });

    it('fixes findings across multiple files', () => {
      const file1 = join(FIXTURE_DIR, 'file1.ts');
      const file2 = join(FIXTURE_DIR, 'file2.ts');
      writeFileSync(file1, 'const url = "http://api.example.com";\n');
      writeFileSync(file2, 'const v = SSLv3;\n');

      const findings = [
        createFinding({ ruleId: 'HIPAA-ENC-001', filePath: file1, lineNumber: 1 }),
        createFinding({ ruleId: 'HIPAA-ENC-005', filePath: file2, lineNumber: 1 }),
      ];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(2);

      expect(readFileSync(file1, 'utf-8')).toContain('https://');
      expect(readFileSync(file2, 'utf-8')).toContain('TLSv1_2');
    });
  });

  // ── Skipping non-fixable rules ──

  describe('non-fixable findings', () => {
    it('skips findings with no auto-fix handler', () => {
      const filePath = join(FIXTURE_DIR, 'skip.ts');
      writeFileSync(filePath, 'console.log(patientName);\n');

      const findings = [
        createFinding({ ruleId: 'HIPAA-PHI-001', filePath, lineNumber: 1 }),
        createFinding({ ruleId: 'HIPAA-AC-001', filePath, lineNumber: 1 }),
      ];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(0);
      expect(result.totalSkipped).toBe(2);
      expect(result.skipped.every((s) => s.reason === 'No auto-fix available for this rule')).toBe(
        true,
      );
    });
  });

  // ── Edge cases ──

  describe('edge cases', () => {
    it('handles line number out of range', () => {
      const filePath = join(FIXTURE_DIR, 'short.ts');
      writeFileSync(filePath, 'const x = 1;\n');

      const findings = [createFinding({ ruleId: 'HIPAA-ENC-001', filePath, lineNumber: 999 })];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(0);
      expect(result.skipped[0]!.reason).toBe('Line number out of range');
    });

    it('handles non-existent file gracefully', () => {
      const filePath = join(FIXTURE_DIR, 'nonexistent.ts');

      const findings = [createFinding({ ruleId: 'HIPAA-ENC-001', filePath, lineNumber: 1 })];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(0);
      expect(result.skipped[0]!.reason).toBe('Could not read/write file');
    });

    it('returns empty summary when no findings', () => {
      const result = fixer.fix([]);
      expect(result.totalFixed).toBe(0);
      expect(result.totalSkipped).toBe(0);
      expect(result.applied).toEqual([]);
      expect(result.skipped).toEqual([]);
    });

    it('handles line that does not match the expected pattern', () => {
      const filePath = join(FIXTURE_DIR, 'no-match.ts');
      writeFileSync(filePath, 'const x = 42;\n');

      const findings = [createFinding({ ruleId: 'HIPAA-ENC-001', filePath, lineNumber: 1 })];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(0);
      expect(result.skipped[0]!.reason).toBe('Fix could not be applied safely');
    });
  });

  // ── Comment Skipping ──

  describe('comment skipping', () => {
    it('should NOT fix http:// inside a single-line comment', () => {
      const filePath = join(FIXTURE_DIR, 'comment-line.ts');
      writeFileSync(filePath, '// See http://example.com for docs\n');

      const findings = [createFinding({ ruleId: 'HIPAA-ENC-001', filePath, lineNumber: 1 })];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(0);
      expect(result.skipped[0]!.reason).toBe('Line is inside a comment');

      const content = readFileSync(filePath, 'utf-8');
      expect(content).toContain('http://example.com');
    });

    it('should NOT fix http:// inside a block comment', () => {
      const filePath = join(FIXTURE_DIR, 'block-comment.ts');
      writeFileSync(
        filePath,
        ['/*', ' * API endpoint: http://api.example.com', ' */', 'const x = 1;'].join('\n'),
      );

      const findings = [createFinding({ ruleId: 'HIPAA-ENC-001', filePath, lineNumber: 2 })];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(0);
      expect(result.skipped[0]!.reason).toBe('Line is inside a comment');
    });

    it('should NOT fix http:// inside a hash comment', () => {
      const filePath = join(FIXTURE_DIR, 'hash-comment.py');
      writeFileSync(filePath, '# See http://example.com for docs\n');

      const findings = [createFinding({ ruleId: 'HIPAA-ENC-001', filePath, lineNumber: 1 })];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(0);
      expect(result.skipped[0]!.reason).toBe('Line is inside a comment');
    });

    it('should include HTTPS verification warning in fix description', () => {
      const filePath = join(FIXTURE_DIR, 'https-warn.ts');
      writeFileSync(filePath, 'const url = "http://api.example.com";\n');

      const findings = [createFinding({ ruleId: 'HIPAA-ENC-001', filePath, lineNumber: 1 })];

      const result = fixer.fix(findings);
      expect(result.totalFixed).toBe(1);
      expect(result.applied[0]!.description).toContain('verify target supports HTTPS');
    });
  });
});
