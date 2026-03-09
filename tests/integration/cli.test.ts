import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { mkdirSync, rmSync, readdirSync, readFileSync } from 'fs';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';

const execFileAsync = promisify(execFile);

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '../..');
const FIXTURES_ROOT = resolve(__dirname, '../fixtures');
const COMPLIANT_DIR = resolve(FIXTURES_ROOT, 'compliant');
const NON_COMPLIANT_DIR = resolve(FIXTURES_ROOT, 'non-compliant');
const INTEGRATION_TMP = resolve(FIXTURES_ROOT, 'integration-cli');
const CLI_ENTRY = resolve(PROJECT_ROOT, 'src/cli/index.ts');

beforeAll(() => {
  mkdirSync(INTEGRATION_TMP, { recursive: true });
});

afterAll(() => {
  rmSync(INTEGRATION_TMP, { recursive: true, force: true });
});

/**
 * Run the CLI as a subprocess using node --import tsx.
 */
async function runCLI(
  args: string[],
  timeout = 20000,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  try {
    const { stdout, stderr } = await execFileAsync(
      process.execPath,
      ['--import', 'tsx', CLI_ENTRY, ...args],
      { timeout, env: { ...process.env }, cwd: PROJECT_ROOT },
    );
    return { stdout, stderr, exitCode: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; code?: number | string };
    const exitCode = typeof e.code === 'number' ? e.code : 1;
    return {
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? '',
      exitCode,
    };
  }
}

/**
 * Extract JSON from stdout that may contain leading progress text.
 */
function extractJSON(stdout: string): unknown {
  const start = stdout.indexOf('{');
  const startArr = stdout.indexOf('[');
  const idx = start === -1 ? startArr : startArr === -1 ? start : Math.min(start, startArr);
  if (idx === -1) throw new Error('No JSON found in stdout');
  return JSON.parse(stdout.slice(idx));
}

// ──────────────────────────────────────────────────
// scan command
// ──────────────────────────────────────────────────

describe('CLI: scan', () => {
  it('should scan a directory and output results', async () => {
    const { stdout, exitCode } = await runCLI(['scan', COMPLIANT_DIR]);
    // Compliant fixture still triggers PHI-001 (patientId in log), so exit 1
    expect(exitCode).toBe(1);
    expect(stdout).toContain('Files scanned:');
    expect(stdout).toContain('Rules evaluated:');
  });

  it('should exit 1 for non-compliant directory with critical findings', async () => {
    const { stdout, exitCode } = await runCLI(['scan', NON_COMPLIANT_DIR]);
    expect(exitCode).toBe(1);
    expect(stdout).toContain('does not guarantee HIPAA compliance');
  });

  it('should output valid JSON with --json flag', async () => {
    const { stdout, exitCode } = await runCLI(['scan', NON_COMPLIANT_DIR, '--json']);
    // --json returns before process.exit(1)
    expect(exitCode).toBe(0);
    const parsed = extractJSON(stdout) as Record<string, unknown>;
    expect(Array.isArray(parsed.findings)).toBe(true);
    expect((parsed.findings as unknown[]).length).toBeGreaterThan(0);
    expect(parsed.rulesEvaluated).toBe(43);
    expect(parsed.scanDurationMs as number).toBeGreaterThanOrEqual(0);
  });

  it('should exit 2 for invalid path', async () => {
    const { stderr, exitCode } = await runCLI(['scan', '/nonexistent/path/xyz']);
    expect(exitCode).toBe(2);
    expect(stderr).toContain('Security Error');
  });
});

// ──────────────────────────────────────────────────
// score command
// ──────────────────────────────────────────────────

describe('CLI: score', () => {
  it('should exit 0 for compliant directory', async () => {
    const { stdout, exitCode } = await runCLI(['score', COMPLIANT_DIR]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('Overall:');
  });

  it('should output valid JSON with --json flag', async () => {
    const { stdout, exitCode } = await runCLI(['score', NON_COMPLIANT_DIR, '--json']);
    expect(exitCode).toBe(0);
    const parsed = JSON.parse(stdout);
    expect(typeof parsed.overallScore).toBe('number');
    expect(parsed.overallScore).toBeGreaterThanOrEqual(0);
    expect(parsed.overallScore).toBeLessThanOrEqual(100);
    expect(['strong', 'needs_improvement', 'at_risk', 'critical']).toContain(parsed.band);
    expect(Object.keys(parsed.domainScores).length).toBe(6);
    expect(parsed.metadata.rulesEvaluated).toBe(43);
  });

  it('should exit 1 when score is below threshold', async () => {
    const { stdout, exitCode } = await runCLI(['score', NON_COMPLIANT_DIR, '--threshold', '90']);
    expect(exitCode).toBe(1);
    expect(stdout).toContain('below threshold');
  });

  it('should exit 2 for invalid path', async () => {
    const { stderr, exitCode } = await runCLI(['score', '/nonexistent/path/xyz']);
    expect(exitCode).toBe(2);
    expect(stderr).toContain('Security Error');
  });
});

// ──────────────────────────────────────────────────
// report command
// ──────────────────────────────────────────────────

describe('CLI: report', () => {
  it('should generate a JSON report in specified output directory', async () => {
    const outputDir = join(INTEGRATION_TMP, 'report-cli-1');
    mkdirSync(outputDir, { recursive: true });

    const { stdout, exitCode } = await runCLI(['report', NON_COMPLIANT_DIR, '--output', outputDir]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('Report saved:');

    const files = readdirSync(outputDir).filter((f) => f.startsWith('hipaalint-report-'));
    expect(files.length).toBeGreaterThan(0);

    const parsed = JSON.parse(readFileSync(join(outputDir, files[0]!), 'utf-8'));
    expect(parsed).toHaveProperty('id');
    expect(parsed).toHaveProperty('version');
    expect(parsed).toHaveProperty('score');
  });

  it('should default to JSON format', async () => {
    const outputDir = join(INTEGRATION_TMP, 'report-cli-default');
    mkdirSync(outputDir, { recursive: true });

    const { stdout, exitCode } = await runCLI(['report', COMPLIANT_DIR, '--output', outputDir]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('JSON');

    const files = readdirSync(outputDir).filter((f) => f.endsWith('.json'));
    expect(files.length).toBeGreaterThan(0);
  });

  it('should exit 2 for invalid path', async () => {
    const { stderr, exitCode } = await runCLI(['report', '/nonexistent/path/xyz']);
    expect(exitCode).toBe(2);
    expect(stderr).toContain('Security Error');
  });
});

// ──────────────────────────────────────────────────
// phi command
// ──────────────────────────────────────────────────

describe('CLI: phi', () => {
  it('should exit 1 and report PHI for non-compliant fixture', async () => {
    const { stdout, exitCode } = await runCLI([
      'phi',
      join(NON_COMPLIANT_DIR, 'healthcare-api.ts'),
    ]);
    expect(exitCode).toBe(1);
    expect(stdout).toContain('PHI Detection Results');
    expect(stdout).toContain('potential PHI exposure');
  });

  it('should exit 0 for compliant fixture with no PHI', async () => {
    const { stdout, exitCode } = await runCLI(['phi', join(COMPLIANT_DIR, 'healthcare-api.ts')]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('No PHI detected');
  });

  it('should exit 2 for nonexistent file', async () => {
    const { stderr, exitCode } = await runCLI(['phi', '/nonexistent/file.ts']);
    expect(exitCode).toBe(2);
    expect(stderr).toContain('Security Error');
  });
});

// ──────────────────────────────────────────────────
// rules command
// ──────────────────────────────────────────────────

describe('CLI: rules', () => {
  it('should exit 0 and list rules', async () => {
    const { stdout, exitCode } = await runCLI(['rules']);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('HipaaLint Rules');
    expect(stdout).toContain('HIPAA-');
  });

  it('should output valid JSON array with --json flag', async () => {
    const { stdout, exitCode } = await runCLI(['rules', '--json']);
    expect(exitCode).toBe(0);
    const parsed = JSON.parse(stdout);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBe(266);
    for (const r of parsed) {
      expect(r.ruleId).toBeDefined();
      expect(r.severity).toBeDefined();
      expect(r.category).toBeDefined();
    }
  });

  it('should filter rules by category', async () => {
    const { stdout, exitCode } = await runCLI(['rules', '--category', 'phi_protection', '--json']);
    expect(exitCode).toBe(0);
    const parsed = JSON.parse(stdout);
    expect(parsed.length).toBeGreaterThan(0);
    for (const r of parsed) {
      expect(r.category).toBe('phi_protection');
    }
  });
});
