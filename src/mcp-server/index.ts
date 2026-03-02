#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { RuleEvaluator } from '../engine/rule-evaluator.js';
import { ScoreCalculator } from '../engine/score-calculator.js';
import { generateJsonReport } from '../reports/json-report.js';
import { generatePdfReport } from '../reports/pdf-report.js';
import type { ComplianceFinding, ComplianceReport } from '../engine/types.js';
import { randomUUID } from 'crypto';
import { basename } from 'path';
import {
  SecurityError,
  validateScanPath,
  validateOutputDirectory,
  MCPScanArgsSchema,
  MCPScoreArgsSchema,
  MCPReportArgsSchema,
  MCPPHIDetectArgsSchema,
  MCPRulesArgsSchema,
} from '../security/index.js';

// ──────────────────────────────────────────────────
// MCP Server Setup
// ──────────────────────────────────────────────────

const server = new Server(
  {
    name: 'hipaalint-ai',
    version: '0.1.0',
  },
  {
    capabilities: {
      tools: {},
    },
  },
);

// ──────────────────────────────────────────────────
// Tool Definitions
// ──────────────────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'compliance_scan',
      description:
        'Scan a project directory for HIPAA compliance violations. Returns findings grouped by severity with remediation guidance.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          path: {
            type: 'string',
            description: 'Absolute path to the project directory to scan',
          },
          framework: {
            type: 'string',
            description: 'Compliance framework to evaluate against (default: hipaa)',
            default: 'hipaa',
          },
          sensitivity: {
            type: 'string',
            enum: ['strict', 'balanced', 'relaxed'],
            description: 'Detection sensitivity level (default: balanced)',
            default: 'balanced',
          },
        },
        required: ['path'],
      },
    },
    {
      name: 'compliance_score',
      description:
        'Calculate the HipaaLint Score for a project. Returns a weighted score (0-100) across 6 compliance domains.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          path: {
            type: 'string',
            description: 'Absolute path to the project directory',
          },
          framework: {
            type: 'string',
            description: 'Compliance framework (default: hipaa)',
            default: 'hipaa',
          },
          sensitivity: {
            type: 'string',
            enum: ['strict', 'balanced', 'relaxed'],
            description: 'Detection sensitivity (default: balanced)',
            default: 'balanced',
          },
        },
        required: ['path'],
      },
    },
    {
      name: 'compliance_report',
      description:
        'Generate a compliance audit report in JSON or PDF format. Includes executive summary, findings, scores, and remediation recommendations.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          path: {
            type: 'string',
            description: 'Absolute path to the project directory',
          },
          format: {
            type: 'string',
            enum: ['json', 'pdf'],
            description: 'Report format (default: json)',
            default: 'json',
          },
          output: {
            type: 'string',
            description: 'Output file path (optional, defaults to project dir)',
          },
          framework: {
            type: 'string',
            default: 'hipaa',
          },
          sensitivity: {
            type: 'string',
            enum: ['strict', 'balanced', 'relaxed'],
            default: 'balanced',
          },
        },
        required: ['path'],
      },
    },
    {
      name: 'phi_detect',
      description:
        'Detect Protected Health Information (PHI) in a code snippet or file. Returns all detected PHI with HIPAA citation references.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          code: {
            type: 'string',
            description: 'Code content to analyze for PHI',
          },
          filePath: {
            type: 'string',
            description: 'File path for context (e.g. language detection)',
            default: 'unknown.ts',
          },
          sensitivity: {
            type: 'string',
            enum: ['strict', 'balanced', 'relaxed'],
            default: 'balanced',
          },
        },
        required: ['code'],
      },
    },
    {
      name: 'compliance_rules',
      description: 'List or search HIPAA compliance rules in the HipaaLint database.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          action: {
            type: 'string',
            enum: ['list', 'search', 'get'],
            description: 'Action: list all, search by keyword, or get specific rule',
            default: 'list',
          },
          query: {
            type: 'string',
            description: 'Rule ID (for get) or search keyword (for search)',
          },
          category: {
            type: 'string',
            description:
              'Filter by category: phi_protection, encryption, access_control, audit_logging, infrastructure, ai_governance',
          },
          severity: {
            type: 'string',
            description: 'Filter by severity: critical, high, medium, low, info',
          },
        },
      },
    },
  ],
}));

// ──────────────────────────────────────────────────
// Error Helper
// ──────────────────────────────────────────────────

function formatValidationError(err: unknown): string {
  if (err instanceof SecurityError) {
    return `Security Error: ${err.message}`;
  }
  if (err instanceof z.ZodError) {
    return `Validation Error: ${err.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('; ')}`;
  }
  if (err instanceof Error) {
    return err.message;
  }
  return String(err);
}

// ──────────────────────────────────────────────────
// Tool Handlers
// ──────────────────────────────────────────────────

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case 'compliance_scan':
      return handleScan(args as Record<string, unknown>);
    case 'compliance_score':
      return handleScore(args as Record<string, unknown>);
    case 'compliance_report':
      return handleReport(args as Record<string, unknown>);
    case 'phi_detect':
      return handlePHIDetect(args as Record<string, unknown>);
    case 'compliance_rules':
      return handleRules(args as Record<string, unknown>);
    default:
      return { content: [{ type: 'text' as const, text: `Unknown tool: ${name}` }], isError: true };
  }
});

async function handleScan(args: Record<string, unknown>) {
  let validated: z.infer<typeof MCPScanArgsSchema>;
  let path: string;
  try {
    validated = MCPScanArgsSchema.parse(args);
    path = validateScanPath(validated.path);
  } catch (err) {
    return {
      content: [{ type: 'text' as const, text: formatValidationError(err) }],
      isError: true,
    };
  }

  const evaluator = new RuleEvaluator({ sensitivity: validated.sensitivity });
  try {
    const result = evaluator.evaluate([path], validated.framework);

    // Format output
    const criticals = result.findings.filter((f) => f.severity === 'critical');
    const highs = result.findings.filter((f) => f.severity === 'high');
    const mediums = result.findings.filter((f) => f.severity === 'medium');
    const lows = result.findings.filter((f) => f.severity === 'low');

    let output = `# HipaaLint Scan Results\n\n`;
    output += `**Files scanned**: ${result.filesScanned} | **Rules evaluated**: ${result.rulesEvaluated} | **Duration**: ${result.scanDurationMs}ms\n\n`;
    output += `## Summary\n`;
    output += `- 🔴 Critical: ${criticals.length}\n`;
    output += `- 🟠 High: ${highs.length}\n`;
    output += `- 🟡 Medium: ${mediums.length}\n`;
    output += `- 🔵 Low: ${lows.length}\n\n`;

    if (result.findings.length === 0) {
      output += `✅ No compliance violations found!\n`;
    } else {
      for (const [label, icon, findings] of [
        ['Critical', '🔴', criticals],
        ['High', '🟠', highs],
        ['Medium', '🟡', mediums],
        ['Low', '🔵', lows],
      ] as const) {
        if (findings.length > 0) {
          output += `### ${icon} ${label} (${findings.length})\n\n`;
          for (const f of findings) {
            const relPath = f.filePath.replace(path + '/', '');
            output += `- **${f.ruleId}** ${f.title}\n`;
            output += `  📍 \`${relPath}:${f.lineNumber}\`\n`;
            output += `  📋 ${f.citation}\n`;
            output += `  💡 ${f.remediation}\n\n`;
          }
        }
      }
    }

    output += `\n> *Disclaimer: HipaaLint AI is a static analysis helper and does not guarantee HIPAA compliance.*`;

    return { content: [{ type: 'text' as const, text: output }] };
  } finally {
    evaluator.close();
  }
}

async function handleScore(args: Record<string, unknown>) {
  let validated: z.infer<typeof MCPScoreArgsSchema>;
  let path: string;
  try {
    validated = MCPScoreArgsSchema.parse(args);
    path = validateScanPath(validated.path);
  } catch (err) {
    return {
      content: [{ type: 'text' as const, text: formatValidationError(err) }],
      isError: true,
    };
  }

  const evaluator = new RuleEvaluator({ sensitivity: validated.sensitivity });
  try {
    const result = evaluator.evaluate([path], validated.framework);
    const calculator = new ScoreCalculator();
    const score = calculator.calculateScore(result, validated.framework, validated.sensitivity);

    const bandEmoji: Record<string, string> = {
      compliant: '🟢',
      needs_improvement: '🟡',
      at_risk: '🟠',
      critical: '🔴',
    };

    let output = `# HipaaLint Score\n\n`;
    output += `## Overall: ${bandEmoji[score.band]} ${score.overallScore}/100 (${score.band.replace('_', ' ')})\n\n`;
    output += `| Domain | Score | Weight | Pass | Fail | Warn |\n`;
    output += `|--------|-------|--------|------|------|------|\n`;

    for (const [domain, ds] of Object.entries(score.domainScores)) {
      const readable = domain.replace(/([A-Z])/g, ' $1').trim();
      output += `| ${readable} | ${ds.score}/100 | ${(ds.weight * 100).toFixed(0)}% | ${ds.passedCheckpoints} | ${ds.failedCheckpoints} | ${ds.warningCheckpoints} |\n`;
    }

    output += `\n> *Disclaimer: This score is informational only and does not guarantee HIPAA compliance.*`;
    output += `\n*Scanned ${score.metadata.filesScanned} files, ${score.metadata.rulesEvaluated} rules evaluated*\n`;

    return { content: [{ type: 'text' as const, text: output }] };
  } finally {
    evaluator.close();
  }
}

async function handleReport(args: Record<string, unknown>) {
  let validated: z.infer<typeof MCPReportArgsSchema>;
  let path: string;
  let outputDir: string;
  try {
    validated = MCPReportArgsSchema.parse(args);
    path = validateScanPath(validated.path);
    outputDir = validated.output ? validateOutputDirectory(validated.output) : path;
  } catch (err) {
    return {
      content: [{ type: 'text' as const, text: formatValidationError(err) }],
      isError: true,
    };
  }

  const evaluator = new RuleEvaluator({ sensitivity: validated.sensitivity });
  try {
    const result = evaluator.evaluate([path], validated.framework);
    const calculator = new ScoreCalculator();
    const score = calculator.calculateScore(result, validated.framework, validated.sensitivity);

    const report: ComplianceReport = {
      id: randomUUID(),
      version: '0.1.0',
      projectName: basename(path),
      projectPath: path,
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
      recommendations: generateRecommendations(result.findings),
      metadata: {
        hipaalintVersion: '0.1.0',
        rulesVersion: '2025.1',
        frameworksEvaluated: [validated.framework],
        sensitivity: validated.sensitivity,
      },
    };

    let reportPath: string;

    if (validated.format === 'pdf') {
      reportPath = await generatePdfReport(report, outputDir);
    } else {
      reportPath = generateJsonReport(report, outputDir);
    }

    return {
      content: [
        {
          type: 'text' as const,
          text: `✅ Report generated: ${reportPath}\n\nScore: ${score.overallScore}/100 (${score.band})\nFindings: ${result.findings.length}`,
        },
      ],
    };
  } finally {
    evaluator.close();
  }
}

async function handlePHIDetect(args: Record<string, unknown>) {
  let validated: z.infer<typeof MCPPHIDetectArgsSchema>;
  try {
    validated = MCPPHIDetectArgsSchema.parse(args);
  } catch (err) {
    return {
      content: [{ type: 'text' as const, text: formatValidationError(err) }],
      isError: true,
    };
  }

  const { PHIDetector } = await import('../engine/phi-detector.js');
  const detector = new PHIDetector({ sensitivity: validated.sensitivity });
  const findings = detector.detect(validated.code, validated.filePath);

  if (findings.length === 0) {
    return {
      content: [{ type: 'text' as const, text: '✅ No PHI detected in the provided code.' }],
    };
  }

  let output = `# PHI Detection Results\n\n`;
  output += `Found **${findings.length}** potential PHI exposure(s):\n\n`;

  for (const f of findings) {
    output += `- **${f.identifierType}** (${f.confidence} confidence)\n`;
    output += `  Line ${f.lineNumber}, Col ${f.columnNumber} | Context: ${f.context}\n`;
    output += `  📋 ${f.citation}\n\n`;
  }

  return { content: [{ type: 'text' as const, text: output }] };
}

async function handleRules(args: Record<string, unknown>) {
  let validated: z.infer<typeof MCPRulesArgsSchema>;
  try {
    validated = MCPRulesArgsSchema.parse(args);
  } catch (err) {
    return {
      content: [{ type: 'text' as const, text: formatValidationError(err) }],
      isError: true,
    };
  }

  const evaluator = new RuleEvaluator();
  const db = evaluator.getRuleDatabase();

  try {
    let rules;

    switch (validated.action) {
      case 'get':
        if (!validated.query) {
          return {
            content: [{ type: 'text' as const, text: 'Please provide a rule ID.' }],
            isError: true,
          };
        }
        const rule = db.getRule(validated.query);
        if (!rule) {
          return {
            content: [{ type: 'text' as const, text: `Rule not found: ${validated.query}` }],
            isError: true,
          };
        }
        rules = [rule];
        break;

      case 'search':
        if (!validated.query) {
          return {
            content: [{ type: 'text' as const, text: 'Please provide a search keyword.' }],
            isError: true,
          };
        }
        rules = db.searchRules(validated.query);
        break;

      default:
        if (validated.category) {
          rules = db.getRulesByCategory(validated.category, 'hipaa');
        } else if (validated.severity) {
          rules = db.getRulesBySeverity(validated.severity, 'hipaa');
        } else {
          rules = db.getAllRules();
        }
    }

    let output = `# Compliance Rules (${rules.length})\n\n`;
    for (const r of rules) {
      output += `### ${r.ruleId}: ${r.title}\n`;
      output += `**Severity**: ${r.severity} | **Category**: ${r.category}\n`;
      output += `${r.description}\n`;
      output += `📋 ${r.citation}\n`;
      output += `💡 ${r.remediation}\n\n`;
    }

    return { content: [{ type: 'text' as const, text: output }] };
  } finally {
    evaluator.close();
  }
}

function generateRecommendations(findings: ComplianceFinding[]) {
  const recs: ComplianceReport['recommendations'] = [];

  // Group by rule — highest severity first
  const byRule = new Map<string, ComplianceFinding[]>();
  for (const f of findings) {
    const existing = byRule.get(f.ruleId) || [];
    existing.push(f);
    byRule.set(f.ruleId, existing);
  }

  const severityOrder = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
  const sorted = [...byRule.entries()].sort((a, b) => {
    const aMax = Math.min(...a[1].map((f) => severityOrder[f.severity]));
    const bMax = Math.min(...b[1].map((f) => severityOrder[f.severity]));
    return aMax - bMax;
  });

  let priority = 1;
  for (const [ruleId, ruleFindings] of sorted) {
    recs.push({
      priority,
      description: `Fix ${ruleFindings.length} ${ruleFindings[0]!.severity} finding(s): ${ruleFindings[0]!.title}. ${ruleFindings[0]!.remediation}`,
      affectedRules: [ruleId],
    });
    priority++;
  }

  return recs;
}

// ──────────────────────────────────────────────────
// Start Server
// ──────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('HipaaLint AI MCP Server running on stdio');
}

main().catch((error) => {
  console.error('Failed to start MCP server:', error);
  process.exit(1);
});
