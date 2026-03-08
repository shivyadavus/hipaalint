import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { RuleEvaluator } from '../../src/engine/rule-evaluator.js';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';

const FIXTURES_DIR = join(process.cwd(), 'tests', 'fixtures', 'ast-pattern');

describe('Semantic Pattern Evaluation', () => {
  beforeEach(() => {
    mkdirSync(FIXTURES_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(FIXTURES_DIR, { recursive: true, force: true });
  });

  describe('HIPAA-PHI-001: PHI in Log Statements', () => {
    it('should flag console.log with PHI variable name', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'logging.ts'),
        'const patientName = "John";\nconsole.log(patientName);\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-PHI-001');
        expect(findings.length).toBeGreaterThan(0);
        expect(findings[0]!.category).toBe('phi_protection');
      } finally {
        evaluator.close();
      }
    });

    it('should flag logger.info with SSN variable', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'logging.ts'),
        'const ssn = "123-45-6789";\nlogger.info(ssn);\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-PHI-001');
        expect(findings.length).toBeGreaterThan(0);
      } finally {
        evaluator.close();
      }
    });

    it('should flag log call with inline SSN pattern', () => {
      writeFileSync(join(FIXTURES_DIR, 'logging.ts'), 'console.log("SSN: 123-45-6789");\n');

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-PHI-001');
        expect(findings.length).toBeGreaterThan(0);
      } finally {
        evaluator.close();
      }
    });

    it('should NOT flag console.log without PHI', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'logging.ts'),
        'const count = 42;\nconsole.log("Processing", count, "items");\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-PHI-001');
        expect(findings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });

    it('should detect PHI in multi-line log call', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'logging.ts'),
        ['console.log(', '  "Patient:",', '  patientName,', '  dateOfBirth', ');'].join('\n'),
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-PHI-001');
        expect(findings.length).toBeGreaterThan(0);
      } finally {
        evaluator.close();
      }
    });
  });

  describe('HIPAA-PHI-009: PHI in API Response', () => {
    it('should flag res.json returning PHI fields', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'api.ts'),
        'app.get("/patient", (req, res) => {\n  res.json({ ssn: patient.ssn, name: patient.name });\n});\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-PHI-009');
        expect(findings.length).toBeGreaterThan(0);
      } finally {
        evaluator.close();
      }
    });

    it('should NOT flag res.json with safe DTO fields', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'api.ts'),
        'app.get("/status", (req, res) => {\n  res.json({ status: "ok", count: 42 });\n});\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-PHI-009');
        expect(findings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });

    it('should detect PHI in response.send', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'api.ts'),
        'response.send({ diagnosis: record.diagnosis });\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-PHI-009');
        expect(findings.length).toBeGreaterThan(0);
      } finally {
        evaluator.close();
      }
    });
  });

  describe('HIPAA-PHI-010: PHI in Error Messages', () => {
    it('should flag throw with PHI variable in catch block', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'error.ts'),
        [
          'try {',
          '  processRecord();',
          '} catch (e) {',
          '  throw new Error(`Failed for ${patientName}`);',
          '}',
        ].join('\n'),
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-PHI-010');
        expect(findings.length).toBeGreaterThan(0);
      } finally {
        evaluator.close();
      }
    });

    it('should NOT flag throw with generic error message', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'error.ts'),
        [
          'try {',
          '  processRecord();',
          '} catch (e) {',
          '  throw new Error("Processing failed");',
          '}',
        ].join('\n'),
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-PHI-010');
        expect(findings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });

    it('should flag throw with PHI template interpolation', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'error.ts'),
        [
          'try {',
          '  process();',
          '} catch (err) {',
          '  throw new Error(`Error for SSN ${ssn}: ${err.message}`);',
          '}',
        ].join('\n'),
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-PHI-010');
        expect(findings.length).toBeGreaterThan(0);
      } finally {
        evaluator.close();
      }
    });
  });

  describe('HIPAA-AC-001: Missing Authentication Middleware', () => {
    it('should flag route with no auth middleware', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'routes.ts'),
        'app.get("/patients", (req, res) => {\n  res.json(patients);\n});\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-AC-001');
        expect(findings.length).toBeGreaterThan(0);
        expect(findings[0]!.category).toBe('access_control');
      } finally {
        evaluator.close();
      }
    });

    it('should NOT flag route with auth middleware', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'routes.ts'),
        'app.get("/patients", authenticate, (req, res) => {\n  res.json(patients);\n});\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-AC-001');
        expect(findings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });

    it('should NOT flag route with verifyToken middleware', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'routes.ts'),
        'router.post("/records", verifyToken, createRecord);\n',
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-AC-001');
        expect(findings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });

    it('should detect multiple unprotected routes', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'routes.ts'),
        [
          'app.get("/patients", handler);',
          'app.post("/records", handler);',
          'app.delete("/records/:id", handler);',
        ].join('\n'),
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter((f) => f.ruleId === 'HIPAA-AC-001');
        expect(findings.length).toBeGreaterThanOrEqual(3);
      } finally {
        evaluator.close();
      }
    });
  });

  describe('File filtering', () => {
    it('should NOT evaluate JSON files for semantic patterns', () => {
      writeFileSync(
        join(FIXTURES_DIR, 'data.json'),
        JSON.stringify({ patientName: 'John', ssn: '123-45-6789' }),
      );

      const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
      try {
        const result = evaluator.evaluate([FIXTURES_DIR]);
        const findings = result.findings.filter(
          (f) =>
            f.ruleId === 'HIPAA-PHI-001' ||
            f.ruleId === 'HIPAA-PHI-009' ||
            f.ruleId === 'HIPAA-PHI-010' ||
            f.ruleId === 'HIPAA-AC-001',
        );
        expect(findings.length).toBe(0);
      } finally {
        evaluator.close();
      }
    });
  });
});
