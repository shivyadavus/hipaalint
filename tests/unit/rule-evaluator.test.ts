import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { RuleEvaluator } from '../../src/engine/rule-evaluator.js';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';

const FIXTURES_DIR = join(process.cwd(), 'tests', 'fixtures', 'rule-eval');

describe('RuleEvaluator', () => {
  beforeEach(() => {
    mkdirSync(FIXTURES_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(FIXTURES_DIR, { recursive: true, force: true });
  });

  describe('evaluate()', () => {
    it('should return scan result with correct structure', () => {
      writeFileSync(join(FIXTURES_DIR, 'app.ts'), 'const x = 1;\n');

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        expect(result).toHaveProperty('findings');
        expect(result).toHaveProperty('filesScanned');
        expect(result).toHaveProperty('filesSkipped');
        expect(result).toHaveProperty('rulesEvaluated');
        expect(result).toHaveProperty('scanDurationMs');
        expect(result).toHaveProperty('timestamp');
        expect(result.rulesEvaluated).toBe(43);
      } finally {
        evaluator.close();
      }
    });

    it('should scan files recursively', () => {
      mkdirSync(join(FIXTURES_DIR, 'sub'), { recursive: true });
      writeFileSync(join(FIXTURES_DIR, 'app.ts'), 'const x = 1;\n');
      writeFileSync(join(FIXTURES_DIR, 'sub', 'nested.ts'), 'const y = 2;\n');

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        expect(result.filesScanned).toBeGreaterThanOrEqual(2);
      } finally {
        evaluator.close();
      }
    });

    it('should respect ignore patterns', () => {
      mkdirSync(join(FIXTURES_DIR, 'ignored_dir'), { recursive: true });
      writeFileSync(join(FIXTURES_DIR, 'ignored_dir', 'file.ts'), 'const x = 1;\n');

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR], 'hipaa', {
          ignore: ['ignored_dir'],
        });
        expect(result.filesScanned).toBe(0);
      } finally {
        evaluator.close();
      }
    });

    it('should respect maxFiles limit', () => {
      for (let i = 0; i < 5; i++) {
        writeFileSync(join(FIXTURES_DIR, `file${i}.ts`), `const x${i} = ${i};\n`);
      }

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR], 'hipaa', { maxFiles: 2 });
        expect(result.filesScanned).toBeLessThanOrEqual(2);
      } finally {
        evaluator.close();
      }
    });

    it('should skip unsupported file extensions', () => {
      writeFileSync(join(FIXTURES_DIR, 'readme.md'), '# Hello\n');
      writeFileSync(join(FIXTURES_DIR, 'image.png'), 'binary');

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        expect(result.filesScanned).toBe(0);
      } finally {
        evaluator.close();
      }
    });

    it('should deduplicate findings by location', () => {
      // A file that would trigger the same rule on the same line multiple times
      writeFileSync(join(FIXTURES_DIR, 'app.ts'), 'const secretKey = "abc123";\n');

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        // Check that no two findings share the same ruleId:filePath:lineNumber
        const keys = result.findings.map((f) => `${f.ruleId}:${f.filePath}:${f.lineNumber}`);
        const uniqueKeys = new Set(keys);
        expect(keys.length).toBe(uniqueKeys.size);
      } finally {
        evaluator.close();
      }
    });
  });

  describe('code_pattern evaluation', () => {
    it('should detect hardcoded encryption key variables', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'secrets.ts'),
        'const secretKey = "my-super-secret-key";\nconst encryptionKey = "aes-key-12345";\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-ENC-004');
        expect(findings.length).toBeGreaterThan(0);
      } finally {
        evaluator.close();
      }
    });

    it('should detect TLS version violations', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'server.ts'),
        'const options = { secureProtocol: "TLSv1_0" };\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-ENC-005');
        expect(findings.length).toBeGreaterThan(0);
      } finally {
        evaluator.close();
      }
    });
  });

  describe('negative_pattern evaluation', () => {
    it('should flag unencrypted HTTP URLs', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'api.ts'),
        'const apiUrl = "http://api.example.com/patients";\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-ENC-001');
        expect(findings.length).toBeGreaterThan(0);
      } finally {
        evaluator.close();
      }
    });
  });

  describe('import_pattern evaluation', () => {
    it('should flag files missing required security imports', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'server.ts'),
        'import express from "express";\nconst app = express();\napp.listen(3000);\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        // HIPAA-INF-002 requires rate-limit imports, HIPAA-INF-003 requires helmet imports
        const importFindings = result.findings.filter(
          (f) => f.ruleId === 'HIPAA-INF-002' || f.ruleId === 'HIPAA-INF-003',
        );
        expect(importFindings.length).toBeGreaterThan(0);
      } finally {
        evaluator.close();
      }
    });

    it('should NOT flag files with required security imports', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'server.ts'),
        [
          'import express from "express";',
          'import helmet from "helmet";',
          'import rateLimit from "express-rate-limit";',
          'const app = express();',
          'app.use(helmet());',
          'app.use(rateLimit({ windowMs: 15000, max: 100 }));',
        ].join('\n'),
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const infFindings = result.findings.filter(
          (f) => f.ruleId === 'HIPAA-INF-002' || f.ruleId === 'HIPAA-INF-003',
        );
        expect(infFindings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });

    it('should NOT flag AC-004 when Auth0 is imported', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'auth.ts'),
        [
          'import { Auth0Provider } from "@auth0/auth0-react";',
          'import express from "express";',
          'const app = express();',
        ].join('\n'),
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const mfaFindings = result.findings.filter((f) => f.ruleId === 'HIPAA-AC-004');
        expect(mfaFindings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });

    it('should NOT flag AL-001 when @sentry is imported', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'logging.ts'),
        [
          'import * as Sentry from "@sentry/node";',
          'import express from "express";',
          'Sentry.init({ dsn: process.env.SENTRY_DSN });',
        ].join('\n'),
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const auditFindings = result.findings.filter((f) => f.ruleId === 'HIPAA-AL-001');
        expect(auditFindings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });

    it('should skip non-code files for import patterns', () => {
      writeFileSync(join(FIXTURES_DIR, 'config.yaml'), 'server:\n  port: 3000\n');

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const importFindings = result.findings.filter(
          (f) => f.ruleId === 'HIPAA-INF-002' || f.ruleId === 'HIPAA-INF-003',
        );
        expect(importFindings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });
  });

  describe('inline suppression comments', () => {
    it('should suppress specific rule with disable-next-line', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'suppressed.ts'),
        [
          '// hipaalint-disable-next-line HIPAA-ENC-001',
          'const url = "http://api.example.com/data";',
        ].join('\n'),
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const enc001 = result.findings.filter((f) => f.ruleId === 'HIPAA-ENC-001');
        expect(enc001.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });

    it('should suppress all rules with disable-next-line (no rule ID)', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'suppressed-all.ts'),
        [
          '// hipaalint-disable-next-line',
          'const secretKey = "my-secret"; const url = "http://api.example.com";',
        ].join('\n'),
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        // Line 2 should have no findings at all
        const line2Findings = result.findings.filter(
          (f) => f.filePath.includes('suppressed-all') && f.lineNumber === 2,
        );
        expect(line2Findings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });

    it('should suppress current line with disable-line', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'inline.ts'),
        'const url = "http://api.example.com/data"; // hipaalint-disable-line HIPAA-ENC-001\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const enc001 = result.findings.filter(
          (f) => f.ruleId === 'HIPAA-ENC-001' && f.filePath.includes('inline'),
        );
        expect(enc001.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });

    it('should suppress block with disable/enable', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'block.ts'),
        [
          '// hipaalint-disable HIPAA-ENC-001',
          'const url1 = "http://api.example.com/a";',
          'const url2 = "http://api.example.com/b";',
          '// hipaalint-enable HIPAA-ENC-001',
          'const url3 = "http://api.example.com/c";',
        ].join('\n'),
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const enc001 = result.findings.filter(
          (f) => f.ruleId === 'HIPAA-ENC-001' && f.filePath.includes('block'),
        );
        // Lines 2 and 3 suppressed, line 5 should still fire
        expect(enc001.length).toBe(1);
        expect(enc001[0]!.lineNumber).toBe(5);
      } finally {
        evaluator.close();
      }
    });

    it('should still produce findings on non-suppressed lines', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'partial.ts'),
        [
          '// hipaalint-disable-next-line HIPAA-ENC-001',
          'const url1 = "http://api.example.com/a";',
          'const url2 = "http://api.example.com/b";',
        ].join('\n'),
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const enc001 = result.findings.filter(
          (f) => f.ruleId === 'HIPAA-ENC-001' && f.filePath.includes('partial'),
        );
        // Line 2 suppressed, line 3 should fire
        expect(enc001.length).toBe(1);
        expect(enc001[0]!.lineNumber).toBe(3);
      } finally {
        evaluator.close();
      }
    });
  });

  describe('skip reasons tracking', () => {
    it('should track skip reasons for oversized files', () => {
      // Create a file > 1MB
      const largeContent = 'const x = 1;\n'.repeat(100_000);
      writeFileSync(join(FIXTURES_DIR, 'large.ts'), largeContent);

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        expect(result.filesSkipped).toBeGreaterThanOrEqual(1);
        expect(result.skipReasons).toBeDefined();
        expect(result.skipReasons!.tooLarge).toBeGreaterThanOrEqual(1);
      } finally {
        evaluator.close();
      }
    });

    it('should not include skipReasons when no files are skipped', () => {
      writeFileSync(join(FIXTURES_DIR, 'small.ts'), 'const x = 1;\n');

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        expect(result.filesSkipped).toBe(0);
        expect(result.skipReasons).toBeUndefined();
      } finally {
        evaluator.close();
      }
    });
  });

  describe('getRuleDatabase()', () => {
    it('should return the rule database instance', () => {
      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const db = evaluator.getRuleDatabase();
        expect(db).toBeDefined();
        expect(db.getRuleCount()).toBe(266);
      } finally {
        evaluator.close();
      }
    });
  });
});
