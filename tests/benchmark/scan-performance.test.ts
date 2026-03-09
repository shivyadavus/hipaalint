import { describe, it, expect, afterAll } from 'vitest';
import { PHIDetector } from '../../src/engine/phi-detector.js';
import { RuleEvaluator } from '../../src/engine/rule-evaluator.js';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join, resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BENCH_DIR = resolve(__dirname, '../fixtures/benchmark-project');
/**
 * Generate a synthetic TypeScript file with a mix of clean code and PHI patterns.
 */
function generateLargeFile(lineCount: number): string {
  const lines: string[] = [];
  for (let i = 0; i < lineCount; i++) {
    const mod = i % 20;
    switch (mod) {
      case 0:
        lines.push(`const data${i} = fetchRecord(${i});`);
        break;
      case 3:
        lines.push(`const patientName = getPatient(${i});`);
        break;
      case 6:
        lines.push(`console.log("Processing record " + ${i});`);
        break;
      case 9:
        lines.push(`const email = "user${i}@hospital.com";`);
        break;
      case 12:
        lines.push(`const ssn = "123-45-${String(i).padStart(4, '0')}";`);
        break;
      case 15:
        lines.push(`const phone = "(555) 000-${String(i).padStart(4, '0')}";`);
        break;
      default:
        lines.push(`const x${i} = process(${i});`);
        break;
    }
  }
  return lines.join('\n');
}

// Setup benchmark fixtures
mkdirSync(join(BENCH_DIR, 'src'), { recursive: true });
const largeContent = generateLargeFile(1000);
writeFileSync(join(BENCH_DIR, 'src', 'large-file.ts'), largeContent);

// Generate 10 medium files
for (let i = 0; i < 10; i++) {
  writeFileSync(join(BENCH_DIR, 'src', `module-${i}.ts`), generateLargeFile(200));
}

afterAll(() => {
  rmSync(BENCH_DIR, { recursive: true, force: true });
});

describe('Performance Benchmarks', () => {
  it('PHIDetector.detect() should process 1000-line file under 100ms', () => {
    const detector = new PHIDetector({ sensitivity: 'balanced' });

    // Warm up
    detector.detect(largeContent, 'warmup.ts');

    const iterations = 5;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      detector.detect(largeContent, 'test.ts');
    }
    const elapsed = (performance.now() - start) / iterations;

    console.log(`PHIDetector.detect() avg: ${elapsed.toFixed(2)}ms for 1000 lines`);
    expect(elapsed).toBeLessThan(100);
  });

  it('RuleEvaluator.evaluate() should process 10 files under 700ms', () => {
    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      // Warm up
      evaluator.evaluate([BENCH_DIR], 'hipaa');

      const start = performance.now();
      const result = evaluator.evaluate([BENCH_DIR], 'hipaa');
      const elapsed = performance.now() - start;

      console.log(`RuleEvaluator.evaluate() total: ${elapsed.toFixed(2)}ms`);
      console.log(`  Files scanned: ${result.filesScanned}`);
      console.log(`  Findings: ${result.findings.length}`);
      console.log(`  Duration (self-reported): ${result.scanDurationMs}ms`);

      expect(elapsed).toBeLessThan(700);
      expect(result.filesScanned).toBeGreaterThanOrEqual(10);
    } finally {
      evaluator.close();
    }
  });

  it('repeated scans should benefit from regex caching', () => {
    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      // First scan (cold cache)
      const start1 = performance.now();
      evaluator.evaluate([BENCH_DIR], 'hipaa');
      const firstRun = performance.now() - start1;

      // Second scan (warm cache)
      const start2 = performance.now();
      evaluator.evaluate([BENCH_DIR], 'hipaa');
      const secondRun = performance.now() - start2;

      console.log(`First scan: ${firstRun.toFixed(2)}ms, Second scan: ${secondRun.toFixed(2)}ms`);
      console.log(`Cache benefit: ${((1 - secondRun / firstRun) * 100).toFixed(1)}% faster`);

      // Second run should not be significantly slower
      expect(secondRun).toBeLessThanOrEqual(firstRun * 1.5);
    } finally {
      evaluator.close();
    }
  });
});
