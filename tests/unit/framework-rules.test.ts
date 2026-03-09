import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdirSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { RuleEvaluator } from '../../src/engine/rule-evaluator.js';

const FIXTURE_DIR = join(process.cwd(), 'tests', 'fixtures', 'framework-rules');

describe('Expanded framework rules', () => {
  beforeEach(() => {
    mkdirSync(FIXTURE_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(FIXTURE_DIR, { recursive: true, force: true });
  });

  it('fires representative HITRUST crypto and project-scope continuity rules', () => {
    writeFileSync(join(FIXTURE_DIR, 'package.json'), JSON.stringify({ name: 'fixture' }, null, 2));
    writeFileSync(
      join(FIXTURE_DIR, 'crypto.ts'),
      [
        "import { createHash } from 'crypto';",
        "const digest = createHash('md5').update(payload).digest('hex');",
      ].join('\n'),
    );

    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const result = evaluator.evaluate([FIXTURE_DIR], 'hitrust');
      expect(result.findings.some((finding) => finding.ruleId === 'HITRUST-11.A-01')).toBe(true);
      expect(result.findings.some((finding) => finding.ruleId === 'HITRUST-13.A-01')).toBe(true);
    } finally {
      evaluator.close();
    }
  });

  it('fires representative SOC2 unsafe deserialization and continuity rules', () => {
    writeFileSync(join(FIXTURE_DIR, 'package.json'), JSON.stringify({ name: 'fixture' }, null, 2));
    writeFileSync(join(FIXTURE_DIR, 'eval.ts'), 'eval(userSuppliedExpression);\n');

    const evaluator = new RuleEvaluator({ sensitivity: 'balanced' });
    try {
      const result = evaluator.evaluate([FIXTURE_DIR], 'soc2-health');
      expect(result.findings.some((finding) => finding.ruleId === 'SOC2-CC3.2-001')).toBe(true);
      expect(result.findings.some((finding) => finding.ruleId === 'SOC2-CC9.2-001')).toBe(true);
    } finally {
      evaluator.close();
    }
  });
});
