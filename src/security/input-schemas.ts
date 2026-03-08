import { z } from 'zod';
import { SensitivityLevel, ReportFormat, Severity, Category } from '../engine/types.js';

// ──────────────────────────────────────────────────
// CLI Option Schemas
// ──────────────────────────────────────────────────

export const ScanOptionsSchema = z.object({
  framework: z.string().default('hipaa'),
  config: z.string().optional(),
  sensitivity: SensitivityLevel.default('balanced'),
  json: z.boolean().optional(),
  sarif: z.boolean().optional(),
  fix: z.boolean().optional(),
  dryRun: z.boolean().optional(),
  exclude: z.array(z.string()).optional(),
  maxFiles: z
    .string()
    .regex(/^\d+$/, 'maxFiles must be a positive integer')
    .transform(Number)
    .pipe(z.number().int().min(1).max(100_000))
    .default('10000'),
  maxDepth: z
    .string()
    .regex(/^\d+$/, 'maxDepth must be a positive integer')
    .transform(Number)
    .pipe(z.number().int().min(1).max(200))
    .default('50'),
  timeout: z
    .string()
    .regex(/^\d+$/, 'timeout must be a positive integer (ms)')
    .transform(Number)
    .pipe(z.number().int().min(1000).max(300_000))
    .default('60000'),
});

export const ScoreOptionsSchema = z.object({
  framework: z.string().default('hipaa'),
  config: z.string().optional(),
  sensitivity: SensitivityLevel.default('balanced'),
  json: z.boolean().optional(),
  threshold: z
    .string()
    .regex(/^\d+$/, 'threshold must be a non-negative integer')
    .transform(Number)
    .pipe(z.number().int().min(0).max(100))
    .default('0'),
});

export const ReportOptionsSchema = z.object({
  framework: z.string().default('hipaa'),
  config: z.string().optional(),
  sensitivity: SensitivityLevel.default('balanced'),
  format: ReportFormat.default('json'),
  output: z.string().optional(),
});

export const PHIOptionsSchema = z.object({
  sensitivity: SensitivityLevel.default('balanced'),
});

export const RulesOptionsSchema = z.object({
  category: Category.optional(),
  severity: Severity.optional(),
  query: z.string().max(500).optional(),
  json: z.boolean().optional(),
});

// ──────────────────────────────────────────────────
// MCP Tool Argument Schemas
// ──────────────────────────────────────────────────

export const MCPScanArgsSchema = z.object({
  path: z.string().min(1, 'path is required'),
  framework: z.string().default('hipaa'),
  sensitivity: SensitivityLevel.default('balanced'),
  maxDepth: z.number().int().min(1).max(200).default(50),
  timeout: z.number().int().min(1000).max(300_000).default(60_000),
});

export const MCPScoreArgsSchema = z.object({
  path: z.string().min(1, 'path is required'),
  framework: z.string().default('hipaa'),
  sensitivity: SensitivityLevel.default('balanced'),
});

export const MCPReportArgsSchema = z.object({
  path: z.string().min(1, 'path is required'),
  format: ReportFormat.default('json'),
  output: z.string().optional(),
  framework: z.string().default('hipaa'),
  sensitivity: SensitivityLevel.default('balanced'),
});

const MAX_CODE_LENGTH = 512_000; // 500 KB

export const MCPPHIDetectArgsSchema = z.object({
  code: z.string().min(1, 'code is required').max(MAX_CODE_LENGTH, 'code exceeds 500KB limit'),
  filePath: z.string().default('unknown.ts'),
  sensitivity: SensitivityLevel.default('balanced'),
});

export const MCPRulesArgsSchema = z.object({
  action: z.enum(['list', 'search', 'get']).default('list'),
  query: z.string().max(500).optional(),
  category: Category.optional(),
  severity: Severity.optional(),
});
