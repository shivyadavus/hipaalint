#!/usr/bin/env node

import { Command } from 'commander';
import { RuleEvaluator } from '../engine/rule-evaluator.js';
import { ScoreCalculator } from '../engine/score-calculator.js';
import { generateJsonReport, generateSarifReport } from '../reports/json-report.js';
import { generatePdfReport } from '../reports/pdf-report.js';
import { PHIDetector } from '../engine/phi-detector.js';
import type { ComplianceReport, SensitivityLevel } from '../engine/types.js';
import { randomUUID } from 'crypto';
import { resolve, basename } from 'path';
import { readFileSync } from 'fs';

const VERSION = '0.1.0';

const program = new Command();

program
  .name('hipaalint')
  .description('HIPAA compliance enforcement for AI-assisted development')
  .version(VERSION);

// ──────────────────────────────────────────────────
// scan command
// ──────────────────────────────────────────────────

program
  .command('scan')
  .description('Scan a project for compliance violations')
  .argument('[path]', 'Path to scan', '.')
  .option('-f, --framework <framework>', 'Compliance framework', 'hipaa')
  .option('-s, --sensitivity <level>', 'Sensitivity: strict, balanced, relaxed', 'balanced')
  .option('--json', 'Output as JSON')
  .option('--sarif', 'Output as SARIF')
  .option('--max-files <n>', 'Max files to scan', '10000')
  .action(async (path: string, options) => {
    const targetPath = resolve(path);
    const sensitivity = options.sensitivity as SensitivityLevel;

    console.log(`\n🛡️  HipaaLint AI — Scanning...\n`);
    console.log(`   Path: ${targetPath}`);
    console.log(`   Framework: ${options.framework}`);
    console.log(`   Sensitivity: ${sensitivity}\n`);

    const evaluator = new RuleEvaluator({ sensitivity });
    try {
      const result = evaluator.evaluate([targetPath], options.framework, {
        maxFiles: parseInt(options.maxFiles, 10),
      });

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      // Terminal output
      const criticals = result.findings.filter((f) => f.severity === 'critical');
      const highs = result.findings.filter((f) => f.severity === 'high');
      const mediums = result.findings.filter((f) => f.severity === 'medium');
      const lows = result.findings.filter((f) => f.severity === 'low');

      console.log(`📊 Results:`);
      console.log(`   Files scanned: ${result.filesScanned}`);
      console.log(`   Rules evaluated: ${result.rulesEvaluated}`);
      console.log(`   Duration: ${result.scanDurationMs}ms\n`);
      console.log(`   🔴 Critical: ${criticals.length}`);
      console.log(`   🟠 High:     ${highs.length}`);
      console.log(`   🟡 Medium:   ${mediums.length}`);
      console.log(`   🔵 Low:      ${lows.length}\n`);

      if (result.findings.length === 0) {
        console.log(`✅ No compliance violations found!\n`);
        return;
      }

      for (const f of result.findings) {
        const relPath = f.filePath.replace(targetPath + '/', '');
        const icon =
          f.severity === 'critical'
            ? '🔴'
            : f.severity === 'high'
              ? '🟠'
              : f.severity === 'medium'
                ? '🟡'
                : '🔵';
        console.log(`${icon} ${f.ruleId}: ${f.title}`);
        console.log(`   📍 ${relPath}:${f.lineNumber}`);
        console.log(`   📋 ${f.citation}`);
        console.log(`   💡 ${f.remediation}\n`);
      }

      // Set exit code if critical findings exist
      if (criticals.length > 0) {
        console.log(`\n======================================================`);
        console.log(`⚠️  DISCLAIMER: HipaaLint AI is a static analysis`);
        console.log(`   tool and does NOT guarantee full HIPAA compliance.`);
        console.log(`======================================================\n`);
        process.exit(1);
      }
    } finally {
      evaluator.close();
    }
  });

// ──────────────────────────────────────────────────
// score command
// ──────────────────────────────────────────────────

program
  .command('score')
  .description('Calculate the HipaaLint Score')
  .argument('[path]', 'Path to evaluate', '.')
  .option('-f, --framework <framework>', 'Compliance framework', 'hipaa')
  .option('-s, --sensitivity <level>', 'Sensitivity level', 'balanced')
  .option('--json', 'Output as JSON')
  .option('--threshold <score>', 'Fail if score is below threshold', '0')
  .action(async (path: string, options) => {
    const targetPath = resolve(path);
    const sensitivity = options.sensitivity as SensitivityLevel;

    const evaluator = new RuleEvaluator({ sensitivity });
    try {
      const result = evaluator.evaluate([targetPath], options.framework);
      const calculator = new ScoreCalculator();
      const score = calculator.calculateScore(result, options.framework, sensitivity);

      if (options.json) {
        console.log(JSON.stringify(score, null, 2));
        return;
      }

      const bandEmoji: Record<string, string> = {
        compliant: '🟢',
        needs_improvement: '🟡',
        at_risk: '🟠',
        critical: '🔴',
      };

      console.log(`\n🛡️  HipaaLint Score\n`);
      console.log(
        `   ${bandEmoji[score.band]} Overall: ${score.overallScore}/100 (${score.band.replace(/_/g, ' ')})\n`,
      );

      console.log(`   Domain Breakdown:`);
      for (const [domain, ds] of Object.entries(score.domainScores)) {
        const readable = domain.replace(/([A-Z])/g, ' $1').trim();
        const icon = ds.score >= 90 ? '🟢' : ds.score >= 70 ? '🟡' : '🟠';
        console.log(
          `   ${icon} ${readable}: ${ds.score}/100 (${(ds.weight * 100).toFixed(0)}% weight)`,
        );
      }

      console.log(`\n   ⚠️  DISCLAIMER: This score is informational only and`);
      console.log(`      does NOT guarantee full HIPAA compliance.\n`);

      console.log(
        `\n   Files: ${score.metadata.filesScanned} | Rules: ${score.metadata.rulesEvaluated}\n`,
      );

      // Check threshold
      const threshold = parseInt(options.threshold, 10);
      if (threshold > 0 && score.overallScore < threshold) {
        console.log(`❌ Score ${score.overallScore} is below threshold ${threshold}\n`);
        process.exitCode = 1;
      }
    } finally {
      evaluator.close();
    }
  });

// ──────────────────────────────────────────────────
// report command
// ──────────────────────────────────────────────────

program
  .command('report')
  .description('Generate a compliance audit report')
  .argument('[path]', 'Path to analyze', '.')
  .option('-f, --framework <framework>', 'Compliance framework', 'hipaa')
  .option('-s, --sensitivity <level>', 'Sensitivity level', 'balanced')
  .option('--format <format>', 'Report format: json, pdf, sarif', 'json')
  .option('-o, --output <dir>', 'Output directory')
  .action(async (path: string, options) => {
    const targetPath = resolve(path);
    const sensitivity = options.sensitivity as SensitivityLevel;
    const outputDir = options.output ? resolve(options.output) : targetPath;

    console.log(`\n🛡️  Generating ${options.format.toUpperCase()} report...\n`);

    const evaluator = new RuleEvaluator({ sensitivity });
    try {
      const result = evaluator.evaluate([targetPath], options.framework);
      const calculator = new ScoreCalculator();
      const score = calculator.calculateScore(result, options.framework, sensitivity);

      const report: ComplianceReport = {
        id: randomUUID(),
        version: VERSION,
        projectName: basename(targetPath),
        projectPath: targetPath,
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
          hipaalintVersion: VERSION,
          rulesVersion: '2025.1',
          frameworksEvaluated: [options.framework],
          sensitivity,
        },
      };

      let reportPath: string;
      switch (options.format) {
        case 'pdf':
          reportPath = await generatePdfReport(report, outputDir);
          break;
        case 'sarif':
          reportPath = generateSarifReport(report, outputDir);
          break;
        default:
          reportPath = generateJsonReport(report, outputDir);
      }

      console.log(`✅ Report saved: ${reportPath}`);
      console.log(`   Score: ${score.overallScore}/100 (${score.band})`);
      console.log(`   Findings: ${result.findings.length}\n`);
    } finally {
      evaluator.close();
    }
  });

// ──────────────────────────────────────────────────
// phi command
// ──────────────────────────────────────────────────

program
  .command('phi')
  .description('Detect PHI in a file or code snippet')
  .argument('<file>', 'File path to scan for PHI')
  .option('-s, --sensitivity <level>', 'Sensitivity level', 'balanced')
  .action(async (file: string, options) => {
    const filePath = resolve(file);
    const sensitivity = options.sensitivity as SensitivityLevel;

    try {
      const content = readFileSync(filePath, 'utf-8');
      const detector = new PHIDetector({ sensitivity });
      const findings = detector.detect(content, filePath);

      if (findings.length === 0) {
        console.log(`\n✅ No PHI detected in ${file}\n`);
        return;
      }

      console.log(`\n🛡️  PHI Detection Results — ${file}\n`);
      console.log(`   Found ${findings.length} potential PHI exposure(s):\n`);

      for (const f of findings) {
        console.log(`   • ${f.identifierType} (${f.confidence} confidence)`);
        console.log(`     Line ${f.lineNumber}, Col ${f.columnNumber} | Context: ${f.context}`);
        console.log(`     📋 ${f.citation}\n`);
      }

      process.exitCode = 1;
    } catch (_err) {
      console.error(`Error reading file: ${file}`);
      process.exitCode = 1;
    }
  });

// ──────────────────────────────────────────────────
// rules command
// ──────────────────────────────────────────────────

program
  .command('rules')
  .description('List compliance rules')
  .option('-c, --category <category>', 'Filter by category')
  .option('-s, --severity <severity>', 'Filter by severity')
  .option('-q, --query <keyword>', 'Search rules by keyword')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    const evaluator = new RuleEvaluator();
    const db = evaluator.getRuleDatabase();

    try {
      let rules;
      if (options.query) {
        rules = db.searchRules(options.query);
      } else if (options.category) {
        rules = db.getRulesByCategory(options.category, 'hipaa');
      } else if (options.severity) {
        rules = db.getRulesBySeverity(options.severity, 'hipaa');
      } else {
        rules = db.getAllRules();
      }

      if (options.json) {
        console.log(JSON.stringify(rules, null, 2));
        return;
      }

      console.log(`\n🛡️  HipaaLint Rules (${rules.length})\n`);
      for (const r of rules) {
        const icon =
          r.severity === 'critical'
            ? '🔴'
            : r.severity === 'high'
              ? '🟠'
              : r.severity === 'medium'
                ? '🟡'
                : '🔵';
        console.log(`${icon} ${r.ruleId}: ${r.title}`);
        console.log(`   Severity: ${r.severity} | Category: ${r.category}`);
        console.log(`   ${r.description}\n`);
      }
    } finally {
      evaluator.close();
    }
  });

program.parse();
