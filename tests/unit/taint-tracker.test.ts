import { describe, expect, it } from 'vitest';
import { analyzeProjectTaint } from '../../src/engine/taint-tracker.js';
import type { Rule } from '../../src/engine/types.js';

const logRule: Rule = {
  id: 1,
  frameworkId: 1,
  ruleId: 'HIPAA-PHI-001',
  title: 'PHI in Log Statements',
  description: 'Detects PHI in logs.',
  severity: 'critical',
  category: 'phi_protection',
  citation: '45 CFR',
  remediation: 'Do not log PHI.',
  patternType: 'semantic_pattern',
  patternConfig: JSON.stringify({
    functionNames: ['console.log', 'logger.info'],
    checkArguments: true,
  }),
  isRequired: true,
};

const responseRule: Rule = {
  id: 2,
  frameworkId: 1,
  ruleId: 'HIPAA-PHI-009',
  title: 'PHI in API Response',
  description: 'Detects PHI in responses.',
  severity: 'critical',
  category: 'phi_protection',
  citation: '45 CFR',
  remediation: 'Do not return PHI.',
  patternType: 'semantic_pattern',
  patternConfig: JSON.stringify({
    checkForPHIFields: true,
    apiContext: true,
  }),
  isRequired: true,
};

describe('analyzeProjectTaint', () => {
  it('tracks taint through helper calls in the same file', () => {
    const findings = analyzeProjectTaint(
      [
        {
          filePath: '/tmp/log-helper.ts',
          content: [
            'function logPhi(data) {',
            '  console.log(data);',
            '}',
            'const patientRecord = req.body.ssn;',
            'logPhi(patientRecord);',
          ].join('\n'),
        },
      ],
      [logRule],
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]!.lineNumber).toBe(2);
  });

  it('tracks taint across files through imports and function returns', () => {
    const findings = analyzeProjectTaint(
      [
        {
          filePath: '/tmp/source.ts',
          content: [
            'export function getPatientRecord() {',
            '  const { ssn } = req.body;',
            '  return { ssn };',
            '}',
          ].join('\n'),
        },
        {
          filePath: '/tmp/sink.ts',
          content: [
            "import { getPatientRecord } from './source';",
            'const record = getPatientRecord();',
            'logger.info(record);',
          ].join('\n'),
        },
      ],
      [logRule],
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]!.filePath).toBe('/tmp/sink.ts');
    expect(findings[0]!.lineNumber).toBe(3);
  });

  it('tracks template literal interpolation into log sinks', () => {
    const findings = analyzeProjectTaint(
      [
        {
          filePath: '/tmp/template.ts',
          content: [
            'const { ssn } = req.body;',
            'console.log(`Patient SSN ${ssn}`);',
          ].join('\n'),
        },
      ],
      [logRule],
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]!.lineNumber).toBe(2);
  });

  it('tracks object spread and member access into response sinks', () => {
    const findings = analyzeProjectTaint(
      [
        {
          filePath: '/tmp/response.ts',
          content: [
            'const { ssn } = req.body;',
            'const payload = { id: 1, ssn };',
            'const responseBody = { ...payload };',
            'res.json(responseBody);',
          ].join('\n'),
        },
      ],
      [responseRule],
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]!.lineNumber).toBe(4);
  });

  it('does not flag safe helper calls with non-tainted arguments', () => {
    const findings = analyzeProjectTaint(
      [
        {
          filePath: '/tmp/safe.ts',
          content: [
            'function logValue(value) {',
            '  console.log(value);',
            '}',
            'const count = 42;',
            'logValue(count);',
          ].join('\n'),
        },
      ],
      [logRule],
    );

    expect(findings).toHaveLength(0);
  });
});
