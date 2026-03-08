#!/usr/bin/env node

import { Command } from 'commander';
import { z } from 'zod';
import { RuleEvaluator } from '../engine/rule-evaluator.js';
import { ScoreCalculator } from '../engine/score-calculator.js';
import { AutoFixer, getFixableRuleIds } from '../engine/auto-fixer.js';
import { generateJsonReport, generateSarifReport } from '../reports/json-report.js';
import { generatePdfReport } from '../reports/pdf-report.js';
import { PHIDetector } from '../engine/phi-detector.js';
import { buildReport } from '../reports/report-builder.js';
import { loadConfig, mergeWithFlags } from '../engine/config-loader.js';
import { VERSION } from '../version.js';
import { resolve, relative, sep } from 'path';
import { readFileSync } from 'fs';
import {
  SecurityError,
  validateScanPath,
  validateOutputDirectory,
  ScanOptionsSchema,
  ScoreOptionsSchema,
  ReportOptionsSchema,
  PHIOptionsSchema,
  RulesOptionsSchema,
} from '../security/index.js';

// ──────────────────────────────────────────────────
// Graceful shutdown — close resources on interrupt
// ──────────────────────────────────────────────────

const cleanupHandlers: Array<() => void> = [];

function registerCleanup(handler: () => void): void {
  cleanupHandlers.push(handler);
}

function runCleanup(): void {
  for (const handler of cleanupHandlers) {
    try {
      handler();
    } catch {
      // Best-effort cleanup
    }
  }
  cleanupHandlers.length = 0;
}

process.on('SIGINT', () => {
  console.error('\n⚠️  Interrupted — cleaning up...');
  runCleanup();
  process.exit(130);
});

process.on('SIGTERM', () => {
  runCleanup();
  process.exit(143);
});

const program = new Command();

program
  .name('hipaalint')
  .description('HIPAA compliance enforcement for AI-assisted development')
  .version(VERSION);

/**
 * Handle validation errors with a consistent exit code.
 */
function handleValidationError(err: unknown): never {
  if (err instanceof SecurityError) {
    console.error(`\nSecurity Error: ${err.message}\n`);
    process.exit(2);
  }
  if (err instanceof z.ZodError) {
    const messages = err.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join(', ');
    console.error(`\nValidation Error: ${messages}\n`);
    process.exit(2);
  }
  throw err;
}

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
  .option('--fix', 'Auto-fix simple violations (http→https, weak TLS, CORS wildcard)')
  .option('--dry-run', 'Preview fixes without writing changes (requires --fix)')
  .option('-e, --exclude <dirs...>', 'Directories or patterns to exclude (e.g. data vendor)')
  .option('--max-files <n>', 'Max files to scan', '10000')
  .option('--max-depth <n>', 'Max directory depth to traverse', '50')
  .option('--timeout <ms>', 'Scan timeout in milliseconds', '60000')
  .action(async (path: string, options) => {
    let targetPath: string;
    let validated: z.infer<typeof ScanOptionsSchema>;
    try {
      targetPath = validateScanPath(resolve(path));
      validated = ScanOptionsSchema.parse(options);
    } catch (err) {
      handleValidationError(err);
    }

    const jsonOutput = validated.json;
    const sarifOutput = validated.sarif;

    // Load .hipaalintrc and merge with CLI flags
    const projectConfig = loadConfig(targetPath);
    const merged = mergeWithFlags(projectConfig, {
      sensitivity: validated.sensitivity !== 'balanced' ? validated.sensitivity : undefined,
      framework: validated.framework !== 'hipaa' ? validated.framework : undefined,
      exclude: validated.exclude?.length ? validated.exclude : undefined,
      maxFiles: validated.maxFiles !== 10000 ? validated.maxFiles : undefined,
      maxDepth: validated.maxDepth !== 50 ? validated.maxDepth : undefined,
      timeout: validated.timeout !== 60000 ? validated.timeout : undefined,
    });

    if (!jsonOutput && !sarifOutput) {
      console.log(`\n🛡️  HipaaLint AI — Scanning...\n`);
      console.log(`   Path: ${targetPath}`);
      console.log(`   Framework: ${merged.framework}`);
      console.log(`   Sensitivity: ${merged.sensitivity}\n`);
    }

    const evaluator = new RuleEvaluator({ sensitivity: merged.sensitivity as 'strict' | 'balanced' | 'relaxed' });
    registerCleanup(() => evaluator.close());
    try {
      const result = evaluator.evaluate([targetPath], merged.framework, {
        ignore: merged.ignore,
        maxFiles: merged.maxFiles,
        maxDepth: merged.maxDepth,
        timeoutMs: merged.timeout,
      });

      if (jsonOutput) {
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
      if (result.filesSkipped > 0) {
        const parts: string[] = [];
        if (result.skipReasons?.binary) parts.push(`${result.skipReasons.binary} binary`);
        if (result.skipReasons?.tooLarge) parts.push(`${result.skipReasons.tooLarge} too large`);
        if (result.skipReasons?.readError) parts.push(`${result.skipReasons.readError} unreadable`);
        const detail = parts.length > 0 ? ` (${parts.join(', ')})` : '';
        console.log(`   Files skipped: ${result.filesSkipped}${detail}`);
      }
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
        const relPath = relative(targetPath, f.filePath).split(sep).join('/');
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

      // Auto-fix if requested
      if (validated.fix) {
        const fixableFindings = result.findings.filter((f) => getFixableRuleIds().has(f.ruleId));

        if (fixableFindings.length === 0) {
          console.log(`🔧 No auto-fixable violations found.\n`);
        } else {
          const dryRun = validated.dryRun ?? false;
          const fixer = new AutoFixer();
          const fixResult = fixer.fix(fixableFindings, { dryRun });

          if (dryRun) {
            console.log(`🔧 Dry Run — ${fixResult.totalFixed} fix(es) would be applied:\n`);
          } else {
            console.log(`🔧 Applied ${fixResult.totalFixed} auto-fix(es):\n`);
          }

          for (const fix of fixResult.applied) {
            const relPath = relative(targetPath, fix.filePath).split(sep).join('/');
            console.log(`   ✅ ${fix.ruleId} — ${relPath}:${fix.lineNumber}`);
            console.log(`      ${fix.description}`);
            console.log(`      - ${fix.originalLine.trim()}`);
            console.log(`      + ${fix.fixedLine.trim()}\n`);
          }

          if (fixResult.totalSkipped > 0) {
            const unfixable = fixResult.skipped.filter(
              (s) => s.reason === 'No auto-fix available for this rule',
            );
            if (unfixable.length > 0) {
              console.log(
                `   ℹ️  ${unfixable.length} finding(s) require manual remediation (no auto-fix)\n`,
              );
            }
          }
        }
      }

      // Always show disclaimer when findings exist
      console.log(
        `--- This tool does not guarantee HIPAA compliance. Consult qualified professionals. ---\n`,
      );

      // Set exit code if critical findings exist
      if (criticals.length > 0) {
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
    let targetPath: string;
    let validated: z.infer<typeof ScoreOptionsSchema>;
    try {
      targetPath = validateScanPath(resolve(path));
      validated = ScoreOptionsSchema.parse(options);
    } catch (err) {
      handleValidationError(err);
    }

    const sensitivity = validated.sensitivity;

    const evaluator = new RuleEvaluator({ sensitivity });
    registerCleanup(() => evaluator.close());
    try {
      const result = evaluator.evaluate([targetPath], validated.framework);
      const calculator = new ScoreCalculator();
      const score = calculator.calculateScore(result, validated.framework, sensitivity);

      if (validated.json) {
        console.log(JSON.stringify(score, null, 2));
        return;
      }

      const bandEmoji: Record<string, string> = {
        strong: '🟢',
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
      if (validated.threshold > 0 && score.overallScore < validated.threshold) {
        console.log(`❌ Score ${score.overallScore} is below threshold ${validated.threshold}\n`);
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
    let targetPath: string;
    let outputDir: string;
    let validated: z.infer<typeof ReportOptionsSchema>;
    try {
      targetPath = validateScanPath(resolve(path));
      validated = ReportOptionsSchema.parse(options);
      outputDir = validated.output
        ? validateOutputDirectory(resolve(validated.output))
        : targetPath;
    } catch (err) {
      handleValidationError(err);
    }

    const sensitivity = validated.sensitivity;

    console.log(`\n🛡️  Generating ${validated.format.toUpperCase()} report...\n`);

    const evaluator = new RuleEvaluator({ sensitivity });
    registerCleanup(() => evaluator.close());
    try {
      const result = evaluator.evaluate([targetPath], validated.framework);
      const calculator = new ScoreCalculator();
      const score = calculator.calculateScore(result, validated.framework, sensitivity);

      const report = buildReport(result, score, targetPath, validated.framework, sensitivity);

      let reportPath: string;
      switch (validated.format) {
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
      console.log(`   Findings: ${result.findings.length}`);
      console.log(`   Note: This report does not guarantee HIPAA compliance.\n`);
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
    let filePath: string;
    let validated: z.infer<typeof PHIOptionsSchema>;
    try {
      filePath = validateScanPath(resolve(file));
      validated = PHIOptionsSchema.parse(options);
    } catch (err) {
      handleValidationError(err);
    }

    const sensitivity = validated.sensitivity;

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

      console.log(
        `--- This tool does not guarantee HIPAA compliance. Consult qualified professionals. ---\n`,
      );
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
    let validated: z.infer<typeof RulesOptionsSchema>;
    try {
      validated = RulesOptionsSchema.parse(options);
    } catch (err) {
      handleValidationError(err);
    }

    const evaluator = new RuleEvaluator();
    registerCleanup(() => evaluator.close());
    const db = evaluator.getRuleDatabase();

    try {
      let rules;
      if (validated.query) {
        rules = db.searchRules(validated.query);
      } else if (validated.category) {
        rules = db.getRulesByCategory(validated.category, 'hipaa');
      } else if (validated.severity) {
        rules = db.getRulesBySeverity(validated.severity, 'hipaa');
      } else {
        rules = db.getAllRules();
      }

      if (validated.json) {
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
