import type { ComplianceReport } from '../engine/types.js';
import { writeFileSync } from 'fs';
import { join } from 'path';

/**
 * Generate a JSON compliance report file.
 */
export function generateJsonReport(report: ComplianceReport, outputDir: string): string {
  const filename = `hipaalint-report-${report.generatedAt.split('T')[0]}.json`;
  const outputPath = join(outputDir, filename);

  // Create a clean report without circular references
  const cleanReport = {
    ...report,
    score: {
      ...report.score,
      domainScores: Object.fromEntries(
        Object.entries(report.score.domainScores).map(([domain, score]) => [
          domain,
          {
            score: score.score,
            weight: score.weight,
            totalCheckpoints: score.totalCheckpoints,
            passedCheckpoints: score.passedCheckpoints,
            failedCheckpoints: score.failedCheckpoints,
            warningCheckpoints: score.warningCheckpoints,
            findingsCount: score.findings.length,
          },
        ]),
      ),
    },
  };

  writeFileSync(outputPath, JSON.stringify(cleanReport, null, 2), 'utf-8');
  return outputPath;
}

/**
 * Generate a SARIF-format report for GitHub code scanning integration.
 */
export function generateSarifReport(report: ComplianceReport, outputDir: string): string {
  const filename = `hipaalint-results.sarif`;
  const outputPath = join(outputDir, filename);

  const sarif = {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'HipaaLint AI',
            version: report.version,
            informationUri: 'https://github.com/hipaalint/hipaalint-ai',
            rules: report.findings
              .map((f) => f.ruleId)
              .filter((id, idx, arr) => arr.indexOf(id) === idx)
              .map((ruleId) => {
                const finding = report.findings.find((f) => f.ruleId === ruleId)!;
                return {
                  id: ruleId,
                  name: finding.title,
                  shortDescription: { text: finding.title },
                  fullDescription: { text: finding.description },
                  helpUri: `https://hipaalint.dev/rules/${ruleId.toLowerCase()}`,
                  defaultConfiguration: {
                    level:
                      finding.severity === 'critical' || finding.severity === 'high'
                        ? 'error'
                        : 'warning',
                  },
                  properties: {
                    tags: ['security', 'hipaa', finding.category],
                  },
                };
              }),
          },
        },
        results: report.findings.map((f) => ({
          ruleId: f.ruleId,
          level: f.severity === 'critical' || f.severity === 'high' ? 'error' : 'warning',
          message: {
            text: `${f.title}: ${f.description}\n\nRemediation: ${f.remediation}\n\nCitation: ${f.citation}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: f.filePath.replace(report.projectPath + '/', ''),
                },
                region: {
                  startLine: f.lineNumber,
                  startColumn: f.columnNumber,
                },
              },
            },
          ],
          properties: {
            category: f.category,
            confidence: f.confidence,
          },
        })),
      },
    ],
  };

  writeFileSync(outputPath, JSON.stringify(sarif, null, 2), 'utf-8');
  return outputPath;
}
