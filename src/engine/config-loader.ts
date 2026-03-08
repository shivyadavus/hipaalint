import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { z } from 'zod';
import { SensitivityLevel } from './types.js';

// ──────────────────────────────────────────────────
// .hipaalintrc Schema
// ──────────────────────────────────────────────────

const RuleOverride = z.enum(['off', 'warn', 'error']);
type RuleOverride = z.infer<typeof RuleOverride>;

export const HipaaLintConfigSchema = z.object({
  sensitivity: SensitivityLevel.optional(),
  threshold: z.number().min(0).max(100).optional(),
  frameworks: z.array(z.string()).optional(),
  ignore: z.array(z.string()).optional(),
  rules: z.record(z.string(), RuleOverride).optional(),
  maxFiles: z.number().min(1).optional(),
  maxDepth: z.number().min(1).optional(),
  timeout: z.number().min(1000).optional(),
});

export type HipaaLintConfig = z.infer<typeof HipaaLintConfigSchema>;

// Config file names, in priority order
const CONFIG_FILENAMES = ['.hipaalintrc', '.hipaalintrc.json', 'hipaalint.config.json'];

/**
 * Load .hipaalintrc config from a project directory.
 * Searches the directory and parent directories up to the filesystem root.
 *
 * @returns Parsed config, or empty config if no file found.
 */
export function loadConfig(startDir: string, explicitConfigPath?: string): HipaaLintConfig {
  const configPath = explicitConfigPath ? explicitConfigPath : findConfigFile(startDir);
  if (!configPath) return {};

  try {
    const raw = readFileSync(configPath, 'utf-8');
    const parsed = JSON.parse(raw);
    return HipaaLintConfigSchema.parse(parsed);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid .hipaalintrc at ${configPath}: ${msg}`);
  }
}

/**
 * Search for a config file starting from `dir` and walking up.
 */
function findConfigFile(dir: string): string | null {
  let current = dir;
  const root = '/';

  // Walk up at most 20 levels
  for (let i = 0; i < 20; i++) {
    for (const name of CONFIG_FILENAMES) {
      const candidate = join(current, name);
      if (existsSync(candidate)) return candidate;
    }

    const parent = join(current, '..');
    if (parent === current || current === root) break;
    current = parent;
  }

  return null;
}

/**
 * Merge .hipaalintrc defaults with CLI/MCP flags.
 * CLI flags always take precedence over config file values.
 */
export function mergeWithFlags(
  config: HipaaLintConfig,
  flags: {
    sensitivity?: string;
    framework?: string;
    exclude?: string[];
    maxFiles?: number;
    maxDepth?: number;
    timeout?: number;
  },
): {
  sensitivity: string;
  framework: string;
  ignore: string[];
  maxFiles: number;
  maxDepth: number;
  timeout: number;
  ruleOverrides: Record<string, RuleOverride>;
  threshold: number;
} {
  return {
    sensitivity: flags.sensitivity ?? config.sensitivity ?? 'balanced',
    framework: flags.framework ?? config.frameworks?.[0] ?? 'hipaa',
    ignore: flags.exclude ?? config.ignore ?? [],
    maxFiles: flags.maxFiles ?? config.maxFiles ?? 10000,
    maxDepth: flags.maxDepth ?? config.maxDepth ?? 50,
    timeout: flags.timeout ?? config.timeout ?? 60000,
    ruleOverrides: config.rules ?? {},
    threshold: config.threshold ?? 0,
  };
}
