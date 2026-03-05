/**
 * E2E Test: Full project scan end-to-end
 *
 * Creates a realistic multi-file healthcare project structure,
 * then runs the complete pipeline: scan → score → report.
 * Validates that all layers work together correctly.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { RuleEvaluator } from '../../src/engine/rule-evaluator.js';
import { ScoreCalculator } from '../../src/engine/score-calculator.js';
import { generateJsonReport, generateSarifReport } from '../../src/reports/json-report.js';
import type { ComplianceReport } from '../../src/engine/types.js';
import { writeFileSync, mkdirSync, rmSync, readFileSync, existsSync } from 'fs';
import { resolve, dirname, join, basename } from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '../..');
const E2E_PROJECT = resolve(__dirname, '../fixtures/e2e-project');
const CLI_ENTRY = resolve(PROJECT_ROOT, 'src/cli/index.ts');

// ──────────────────────────────────────────────────
// Realistic project file contents
// ──────────────────────────────────────────────────

const FILES: Record<string, string> = {
  // Express server with security middleware
  'src/server.ts': `
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

const app = express();
app.use(helmet());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

app.listen(3000, () => {
  console.log('Server started on port 3000');
});

export default app;
`.trim(),

  // Route with auth middleware — compliant
  'src/routes/patients.ts': `
import { Router } from 'express';
import { authenticate } from '../middleware/auth';

const router = Router();

router.get('/patients/:id', authenticate, (req, res) => {
  const patientId = req.params.id;
  console.log(\`Patient lookup: [ID:\${patientId}]\`);
  res.json({ id: patientId, status: 'active' });
});

export default router;
`.trim(),

  // Route WITHOUT auth — violation HIPAA-AC-001
  'src/routes/admin.ts': `
import { Router } from 'express';

const router = Router();

// Missing auth middleware
router.get('/admin/users', (req, res) => {
  res.json({ users: [] });
});

router.post('/admin/config', (req, res) => {
  res.json({ success: true });
});

export default router;
`.trim(),

  // Service with PHI logging — violation HIPAA-PHI-001
  'src/services/patient-service.ts': `
export class PatientService {
  getPatient(patientName: string, ssn: string) {
    console.log(\`Looking up patient: \${patientName}, SSN: \${ssn}\`);
    return { id: 'P-001', name: patientName };
  }

  updatePatient(patientId: string, data: Record<string, unknown>) {
    console.log(\`Updating patient [ID:\${patientId}]\`);
    return { success: true };
  }
}
`.trim(),

  // Utility with hardcoded secret — violation HIPAA-ENC-004
  'src/utils/crypto.ts': `
import { createCipheriv, randomBytes } from 'crypto';

const secretKey = 'my-hardcoded-secret-key-do-not-use';
const algorithm = 'aes-256-cbc';

export function encrypt(text: string): string {
  const iv = randomBytes(16);
  const cipher = createCipheriv(algorithm, Buffer.from(secretKey), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}
`.trim(),

  // API client with HTTP URL — violation HIPAA-ENC-001
  'src/services/api-client.ts': `
const API_BASE = 'http://api.healthsystem.com/v1';

export async function fetchPatientRecords(token: string) {
  const response = await fetch(\`\${API_BASE}/patients\`, {
    headers: { Authorization: \`Bearer \${token}\` },
  });
  return response.json();
}
`.trim(),

  // Error handler exposing PHI — violation HIPAA-PHI-010
  'src/middleware/error-handler.ts': `
export function errorHandler(err: Error, req: unknown, res: unknown) {
  const patientId = (req as Record<string, string>).patientId;
  try {
    throw new Error(\`Failed processing patient \${patientId}: \${err.message}\`);
  } catch (e) {
    throw new Error(\`Patient error for \${patientId}\`);
  }
}
`.trim(),

  // Config file missing encryption — violation HIPAA-ENC-003
  '.env': `
DATABASE_URL=postgres://localhost:5432/health_db
NODE_ENV=production
PORT=3000
`.trim(),

  // Clean config file
  'tsconfig.json': `{
  "compilerOptions": {
    "target": "ES2022",
    "module": "Node16",
    "strict": true,
    "outDir": "dist"
  }
}`,

  // Clean utility — no violations
  'src/utils/logger.ts': `
export function logEvent(eventType: string, resourceId: string) {
  const timestamp = new Date().toISOString();
  console.log(\`[\${timestamp}] \${eventType}: [ID:\${resourceId}]\`);
}
`.trim(),
};

// ──────────────────────────────────────────────────
// Setup / Teardown
// ──────────────────────────────────────────────────

beforeAll(() => {
  // Create project directory structure
  mkdirSync(E2E_PROJECT, { recursive: true });

  for (const [relativePath, content] of Object.entries(FILES)) {
    const fullPath = join(E2E_PROJECT, relativePath);
    mkdirSync(dirname(fullPath), { recursive: true });
    writeFileSync(fullPath, content);
  }
});

afterAll(() => {
  rmSync(E2E_PROJECT, { recursive: true, force: true });
});

// ──────────────────────────────────────────────────
// Helper
// ──────────────────────────────────────────────────

async function runCLI(
  args: string[],
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  try {
    const { stdout, stderr } = await execFileAsync(
      process.execPath,
      ['--import', 'tsx', CLI_ENTRY, ...args],
      { timeout: 20000, env: { ...process.env }, cwd: PROJECT_ROOT },
    );
    return { stdout, stderr, exitCode: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; code?: number | string };
    const exitCode = typeof e.code === 'number' ? e.code : 1;
    return { stdout: e.stdout ?? '', stderr: e.stderr ?? '', exitCode };
  }
}

// ──────────────────────────────────────────────────
// E2E Tests
// ──────────────────────────────────────────────────

describe('E2E: Full project scan', () => {
  it('should scan all project files and find violations across multiple files', () => {
    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const result = evaluator.evaluate([E2E_PROJECT], 'hipaa');

      // Should scan all .ts and .env files
      expect(result.filesScanned).toBeGreaterThanOrEqual(8);
      expect(result.rulesEvaluated).toBe(29);

      // Should find violations across multiple categories
      const categories = new Set(result.findings.map((f) => f.category));
      expect(categories.has('phi_protection')).toBe(true);
      expect(categories.has('encryption')).toBe(true);

      // Should find violations in different files
      const filesWithFindings = new Set(result.findings.map((f) => basename(f.filePath)));
      expect(filesWithFindings.size).toBeGreaterThanOrEqual(3);

      // Specific violations we planted
      const ruleIds = new Set(result.findings.map((f) => f.ruleId));
      expect(ruleIds.has('HIPAA-ENC-004')).toBe(true); // hardcoded secret in crypto.ts
      expect(ruleIds.has('HIPAA-ENC-001')).toBe(true); // http:// in api-client.ts
      expect(ruleIds.has('HIPAA-ENC-003')).toBe(true); // missing encryption in .env
    } finally {
      evaluator.close();
    }
  });

  it('should calculate a score reflecting the project violations', () => {
    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const result = evaluator.evaluate([E2E_PROJECT], 'hipaa');
      const calculator = new ScoreCalculator();
      const score = calculator.calculateScore(result, 'hipaa', 'balanced');

      // Project has critical violations → score clamped
      expect(score.overallScore).toBeLessThanOrEqual(69);
      expect(['critical', 'at_risk']).toContain(score.band);

      // All 6 domains should have scores
      expect(Object.keys(score.domainScores).length).toBe(6);

      // PHI protection domain should be penalized (PHI in logs)
      expect(score.domainScores.phiProtection.score).toBeLessThan(100);

      // Encryption domain should be penalized (hardcoded key, HTTP)
      expect(score.domainScores.encryption.score).toBeLessThan(100);
    } finally {
      evaluator.close();
    }
  });

  it('should generate a complete JSON report for the project', () => {
    const outputDir = join(E2E_PROJECT, 'reports');
    mkdirSync(outputDir, { recursive: true });

    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const result = evaluator.evaluate([E2E_PROJECT], 'hipaa');
      const calculator = new ScoreCalculator();
      const score = calculator.calculateScore(result, 'hipaa', 'balanced');

      const report: ComplianceReport = {
        id: randomUUID(),
        version: '0.1.0',
        projectName: 'e2e-healthcare-api',
        projectPath: E2E_PROJECT,
        generatedAt: new Date().toISOString(),
        score,
        findings: result.findings,
        summary: {
          totalFindings: result.findings.length,
          bySeverity: {
            critical: result.findings.filter((f) => f.severity === 'critical').length,
            high: result.findings.filter((f) => f.severity === 'high').length,
            medium: result.findings.filter((f) => f.severity === 'medium').length,
            low: result.findings.filter((f) => f.severity === 'low').length,
            info: result.findings.filter((f) => f.severity === 'info').length,
          },
          byCategory: {
            phi_protection: result.findings.filter((f) => f.category === 'phi_protection').length,
            encryption: result.findings.filter((f) => f.category === 'encryption').length,
            access_control: result.findings.filter((f) => f.category === 'access_control').length,
            audit_logging: result.findings.filter((f) => f.category === 'audit_logging').length,
            infrastructure: result.findings.filter((f) => f.category === 'infrastructure').length,
            ai_governance: result.findings.filter((f) => f.category === 'ai_governance').length,
          },
        },
        recommendations: [],
        metadata: {
          hipaalintVersion: '0.1.0',
          rulesVersion: '2025.1',
          frameworksEvaluated: ['hipaa'],
          sensitivity: 'balanced',
        },
      };

      const reportPath = generateJsonReport(report, outputDir);
      expect(existsSync(reportPath)).toBe(true);

      const parsed = JSON.parse(readFileSync(reportPath, 'utf-8'));
      expect(parsed.summary.totalFindings).toBeGreaterThan(0);
      expect(parsed.score.overallScore).toBeLessThanOrEqual(100);
      expect(parsed.metadata.frameworksEvaluated).toContain('hipaa');
    } finally {
      evaluator.close();
    }
  });

  it('should generate a valid SARIF report', () => {
    const outputDir = join(E2E_PROJECT, 'reports');
    mkdirSync(outputDir, { recursive: true });

    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const result = evaluator.evaluate([E2E_PROJECT], 'hipaa');
      const calculator = new ScoreCalculator();
      const score = calculator.calculateScore(result, 'hipaa', 'balanced');

      const report: ComplianceReport = {
        id: randomUUID(),
        version: '0.1.0',
        projectName: 'e2e-healthcare-api',
        projectPath: E2E_PROJECT,
        generatedAt: new Date().toISOString(),
        score,
        findings: result.findings,
        summary: {
          totalFindings: result.findings.length,
          bySeverity: {
            critical: result.findings.filter((f) => f.severity === 'critical').length,
            high: result.findings.filter((f) => f.severity === 'high').length,
            medium: result.findings.filter((f) => f.severity === 'medium').length,
            low: result.findings.filter((f) => f.severity === 'low').length,
            info: result.findings.filter((f) => f.severity === 'info').length,
          },
          byCategory: {
            phi_protection: result.findings.filter((f) => f.category === 'phi_protection').length,
            encryption: result.findings.filter((f) => f.category === 'encryption').length,
            access_control: result.findings.filter((f) => f.category === 'access_control').length,
            audit_logging: result.findings.filter((f) => f.category === 'audit_logging').length,
            infrastructure: result.findings.filter((f) => f.category === 'infrastructure').length,
            ai_governance: result.findings.filter((f) => f.category === 'ai_governance').length,
          },
        },
        recommendations: [],
        metadata: {
          hipaalintVersion: '0.1.0',
          rulesVersion: '2025.1',
          frameworksEvaluated: ['hipaa'],
          sensitivity: 'balanced',
        },
      };

      const sarifPath = generateSarifReport(report, outputDir);
      expect(existsSync(sarifPath)).toBe(true);

      const sarif = JSON.parse(readFileSync(sarifPath, 'utf-8'));
      expect(sarif.$schema).toContain('sarif');
      expect(sarif.runs.length).toBe(1);
      expect(sarif.runs[0].results.length).toBeGreaterThan(0);
      expect(sarif.runs[0].tool.driver.name).toBe('HipaaLint AI');
    } finally {
      evaluator.close();
    }
  });

  it('should produce consistent results across sensitivity levels', () => {
    const results: Record<string, number> = {};
    for (const sensitivity of ['strict', 'balanced', 'relaxed'] as const) {
      const evaluator = new RuleEvaluator({ sensitivity });
      try {
        const result = evaluator.evaluate([E2E_PROJECT], 'hipaa');
        results[sensitivity] = result.findings.length;
      } finally {
        evaluator.close();
      }
    }

    // Strict should find the most, relaxed the least
    expect(results.strict!).toBeGreaterThanOrEqual(results.balanced!);
    expect(results.balanced!).toBeGreaterThanOrEqual(results.relaxed!);
  });

  it('should work end-to-end via the CLI', async () => {
    const outputDir = join(E2E_PROJECT, 'cli-reports');
    mkdirSync(outputDir, { recursive: true });

    // Run scan --json
    const scanResult = await runCLI(['scan', E2E_PROJECT, '--json']);
    expect(scanResult.exitCode).toBe(0);
    const jsonStart = scanResult.stdout.indexOf('{');
    const scanData = JSON.parse(scanResult.stdout.slice(jsonStart));
    expect(scanData.findings.length).toBeGreaterThan(0);
    expect(scanData.filesScanned).toBeGreaterThanOrEqual(8);

    // Run score --json
    const scoreResult = await runCLI(['score', E2E_PROJECT, '--json']);
    expect(scoreResult.exitCode).toBe(0);
    const scoreStart = scoreResult.stdout.indexOf('{');
    const scoreData = JSON.parse(scoreResult.stdout.slice(scoreStart));
    expect(scoreData.overallScore).toBeLessThanOrEqual(69);
    expect(Object.keys(scoreData.domainScores).length).toBe(6);

    // Run report
    const reportResult = await runCLI(['report', E2E_PROJECT, '--output', outputDir]);
    expect(reportResult.exitCode).toBe(0);
    expect(reportResult.stdout).toContain('Report saved:');
  });

  it('should respect ignore patterns for node_modules-like dirs', () => {
    // Create a fake node_modules dir with violations
    const nmDir = join(E2E_PROJECT, 'node_modules', 'some-lib');
    mkdirSync(nmDir, { recursive: true });
    writeFileSync(
      join(nmDir, 'index.ts'),
      'const secret = "hardcoded-key"; const apiUrl = "http://evil.com/api";',
    );

    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const result = evaluator.evaluate([E2E_PROJECT], 'hipaa');
      // No findings should come from node_modules
      const nmFindings = result.findings.filter((f) => f.filePath.includes('node_modules'));
      expect(nmFindings.length).toBe(0);
    } finally {
      evaluator.close();
      // Clean up
      rmSync(join(E2E_PROJECT, 'node_modules'), { recursive: true, force: true });
    }
  });

  it('should respect maxFiles limit', () => {
    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const result = evaluator.evaluate([E2E_PROJECT], 'hipaa', { maxFiles: 2 });
      expect(result.filesScanned).toBeLessThanOrEqual(2);
    } finally {
      evaluator.close();
    }
  });
});
