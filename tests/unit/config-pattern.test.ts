import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { RuleEvaluator } from '../../src/engine/rule-evaluator.js';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';

const FIXTURES_DIR = join(process.cwd(), 'tests', 'fixtures', 'config-pattern');

describe('Config Pattern Evaluation', () => {
  beforeEach(() => {
    mkdirSync(FIXTURES_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(FIXTURES_DIR, { recursive: true, force: true });
  });

  describe('HIPAA-ENC-003: Missing Encryption at Rest', () => {
    it('should flag .env file missing encryption settings', () => {
      writeFileSync(
        join(FIXTURES_DIR, '.env'),
        'DATABASE_URL=postgres://localhost:5432/mydb\nNODE_ENV=production\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const encFindings = result.findings.filter((f) => f.ruleId === 'HIPAA-ENC-003');
        expect(encFindings.length).toBeGreaterThan(0);
        expect(encFindings[0]!.category).toBe('encryption');
      } finally {
        evaluator.close();
      }
    });

    it('should NOT flag .env file with encryption settings', () => {
      writeFileSync(
        join(FIXTURES_DIR, '.env'),
        'DATABASE_URL=postgres://localhost:5432/mydb\nENCRYPTION=aes-256-gcm\nssl=true\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const encFindings = result.findings.filter((f) => f.ruleId === 'HIPAA-ENC-003');
        expect(encFindings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });

    it('should NOT flag .env file with ssl setting', () => {
      writeFileSync(
        join(FIXTURES_DIR, '.env'),
        'DATABASE_URL=postgres://localhost:5432/mydb?ssl=true\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const encFindings = result.findings.filter((f) => f.ruleId === 'HIPAA-ENC-003');
        expect(encFindings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });
  });

  describe('HIPAA-AC-003: Session Timeout Configuration', () => {
    it('should flag .env file missing session timeout', () => {
      writeFileSync(join(FIXTURES_DIR, '.env'), 'APP_NAME=healthcare\nPORT=3000\n');

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const sessionFindings = result.findings.filter((f) => f.ruleId === 'HIPAA-AC-003');
        expect(sessionFindings.length).toBeGreaterThan(0);
      } finally {
        evaluator.close();
      }
    });

    it('should NOT flag .env file with SESSION_TIMEOUT', () => {
      writeFileSync(join(FIXTURES_DIR, '.env'), 'SESSION_TIMEOUT=1800000\nPORT=3000\n');

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const sessionFindings = result.findings.filter((f) => f.ruleId === 'HIPAA-AC-003');
        expect(sessionFindings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });
  });

  describe('HIPAA-AL-003: Log Retention Configuration', () => {
    it('should flag .env file missing log retention', () => {
      writeFileSync(join(FIXTURES_DIR, '.env'), 'LOG_LEVEL=info\n');

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const retentionFindings = result.findings.filter((f) => f.ruleId === 'HIPAA-AL-003');
        expect(retentionFindings.length).toBeGreaterThan(0);
      } finally {
        evaluator.close();
      }
    });

    it('should NOT flag .env file with LOG_RETENTION', () => {
      writeFileSync(join(FIXTURES_DIR, '.env'), 'LOG_RETENTION=2190d\nLOG_LEVEL=info\n');

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const retentionFindings = result.findings.filter((f) => f.ruleId === 'HIPAA-AL-003');
        expect(retentionFindings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });
  });

  describe('HIPAA-AI-002: Missing AI Data Governance', () => {
    it('should flag .env file missing AI governance settings', () => {
      writeFileSync(join(FIXTURES_DIR, '.env'), 'OPENAI_API_KEY=sk-xxx\n');

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const aiFindings = result.findings.filter((f) => f.ruleId === 'HIPAA-AI-002');
        expect(aiFindings.length).toBeGreaterThan(0);
      } finally {
        evaluator.close();
      }
    });

    it('should NOT flag .env file with data_governance setting', () => {
      writeFileSync(
        join(FIXTURES_DIR, '.env'),
        'OPENAI_API_KEY=sk-xxx\ndata_governance=strict\nphi_exclusion=true\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const aiFindings = result.findings.filter((f) => f.ruleId === 'HIPAA-AI-002');
        expect(aiFindings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });
  });

  describe('File matching', () => {
    it('should NOT evaluate non-config files for config patterns', () => {
      // Write a .ts file that has no config settings — should NOT trigger config_pattern rules
      writeFileSync(join(FIXTURES_DIR, 'app.ts'), 'const x = 1;\nexport default x;\n');

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        // Should not have any config_pattern findings for a .ts file
        const configFindings = result.findings.filter(
          (f) =>
            f.ruleId === 'HIPAA-ENC-003' ||
            f.ruleId === 'HIPAA-AC-003' ||
            f.ruleId === 'HIPAA-AL-003' ||
            f.ruleId === 'HIPAA-AI-002',
        );
        expect(configFindings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });

    it('should evaluate database config files', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'database.json'),
        JSON.stringify({ host: 'localhost', port: 5432, database: 'health_db' }),
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        // HIPAA-ENC-003 checks database.* files for encryption config
        const encFindings = result.findings.filter((f) => f.ruleId === 'HIPAA-ENC-003');
        expect(encFindings.length).toBeGreaterThan(0);
      } finally {
        evaluator.close();
      }
    });
  });
});
