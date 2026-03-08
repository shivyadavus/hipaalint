import type { ComplianceFinding, Rule, ScanResult, SensitivityLevel } from './types.js';
import { PHIDetector } from './phi-detector.js';
import { RegexCache } from './regex-cache.js';
import { RuleDatabase } from '../rules/rule-loader.js';
import { validateScanPath } from '../security/index.js';
import { readFileSync, readdirSync, lstatSync, existsSync } from 'fs';
import { join, extname, basename, dirname } from 'path';

// ──────────────────────────────────────────────────
// Inline Suppression Comments
// ──────────────────────────────────────────────────

// Suppression comment patterns:
//   // hipaalint-disable-next-line [RULE-ID]
//   // hipaalint-disable-line [RULE-ID]
//   // hipaalint-disable [RULE-ID]    (block start)
//   // hipaalint-enable [RULE-ID]     (block end)
//   # hipaalint-disable-next-line [RULE-ID]   (Python/YAML style)

const DISABLE_NEXT_LINE = /(?:\/\/|#)\s*hipaalint-disable-next-line(?:\s+([\w-]+))?\s*$/;
const DISABLE_LINE = /(?:\/\/|#)\s*hipaalint-disable-line(?:\s+([\w-]+))?\s*$/;
const DISABLE_BLOCK = /(?:\/\/|#)\s*hipaalint-disable(?:\s+([\w-]+))?\s*$/;
const ENABLE_BLOCK = /(?:\/\/|#)\s*hipaalint-enable(?:\s+([\w-]+))?\s*$/;

type SuppressionEntry = Set<string> | 'all';

/**
 * Build a map of which lines are suppressed and for which rules.
 * Returns a Map<lineIndex (0-based), Set<ruleId> | 'all'>.
 */
function buildSuppressionMap(lines: string[]): Map<number, SuppressionEntry> {
  const map = new Map<number, SuppressionEntry>();
  // Track active block suppressions: Map<ruleId | 'all', true>
  const activeBlocks = new Map<string, boolean>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    // Check for block enable (must come before block disable to handle same-line)
    const enableMatch = ENABLE_BLOCK.exec(line);
    if (enableMatch) {
      const ruleId = enableMatch[1] ?? 'all';
      activeBlocks.delete(ruleId);
      // If enabling a specific rule but 'all' is still active, don't fully clear
    }

    // Check for block disable
    const disableMatch = DISABLE_BLOCK.exec(line);
    if (disableMatch) {
      const ruleId = disableMatch[1] ?? 'all';
      activeBlocks.set(ruleId, true);
    }

    // Check for disable-next-line
    const nextLineMatch = DISABLE_NEXT_LINE.exec(line);
    if (nextLineMatch && i + 1 < lines.length) {
      const ruleId = nextLineMatch[1];
      const nextIdx = i + 1;
      const existing = map.get(nextIdx);
      if (existing === 'all') {
        // Already fully suppressed
      } else if (!ruleId) {
        map.set(nextIdx, 'all');
      } else if (existing instanceof Set) {
        existing.add(ruleId);
      } else {
        map.set(nextIdx, new Set([ruleId]));
      }
    }

    // Check for disable-line (current line)
    const lineMatch = DISABLE_LINE.exec(line);
    if (lineMatch) {
      const ruleId = lineMatch[1];
      const existing = map.get(i);
      if (existing === 'all') {
        // Already fully suppressed
      } else if (!ruleId) {
        map.set(i, 'all');
      } else if (existing instanceof Set) {
        existing.add(ruleId);
      } else {
        map.set(i, new Set([ruleId]));
      }
    }

    // Apply active block suppressions to current line
    if (activeBlocks.size > 0) {
      if (activeBlocks.has('all')) {
        map.set(i, 'all');
      } else {
        const existing = map.get(i);
        if (existing !== 'all') {
          const merged = existing instanceof Set ? existing : new Set<string>();
          for (const ruleId of activeBlocks.keys()) {
            merged.add(ruleId);
          }
          map.set(i, merged);
        }
      }
    }
  }

  return map;
}

/**
 * Check if a finding is suppressed by the suppression map.
 */
function isSuppressed(
  suppressionMap: Map<number, SuppressionEntry>,
  lineIndex: number,
  ruleId: string,
): boolean {
  const entry = suppressionMap.get(lineIndex);
  if (!entry) return false;
  if (entry === 'all') return true;
  return entry.has(ruleId);
}

// ──────────────────────────────────────────────────
// Supported extensions
// ──────────────────────────────────────────────────

const SUPPORTED_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.py',
  '.pyi',
  '.java',
  '.go',
  '.json',
  '.yaml',
  '.yml',
  '.toml',
]);

// Dotfiles where extname() returns '' or wrong value — match by full filename or prefix
function isSupportedFilename(name: string): boolean {
  const lower = name.toLowerCase();
  return lower === '.env' || lower.startsWith('.env.');
}

// ──────────────────────────────────────────────────
// Binary File Detection
// ──────────────────────────────────────────────────

/**
 * Check if file content appears to be binary (contains null bytes).
 * Only checks the first 8KB for efficiency.
 */
function isBinaryContent(content: string): boolean {
  const checkLength = Math.min(content.length, 8192);
  for (let i = 0; i < checkLength; i++) {
    if (content.charCodeAt(i) === 0) return true;
  }
  return false;
}

const DEFAULT_IGNORE = [
  'node_modules',
  'dist',
  'build',
  '.git',
  'coverage',
  '.next',
  '.nuxt',
  '__pycache__',
  '.venv',
  'venv',
  '.idea',
  '.vscode',
  '.DS_Store',
];

/**
 * Load ignore patterns from a .hipaalintignore file.
 * Format: one pattern per line, # for comments, blank lines ignored.
 */
function loadIgnoreFile(dir: string): string[] {
  const ignorePath = join(dir, '.hipaalintignore');
  if (!existsSync(ignorePath)) return [];
  try {
    const content = readFileSync(ignorePath, 'utf-8');
    return content
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('#'));
  } catch {
    return [];
  }
}

// ──────────────────────────────────────────────────
// Rule Evaluator
// ──────────────────────────────────────────────────

export class RuleEvaluator {
  private phiDetector: PHIDetector;
  private ruleDb: RuleDatabase;
  private sensitivity: SensitivityLevel;
  private regexCache: RegexCache;
  private parsedConfigCache = new Map<string, Record<string, unknown>>();

  constructor(options: { dbPath?: string; sensitivity?: SensitivityLevel } = {}) {
    this.sensitivity = options.sensitivity ?? 'balanced';
    this.phiDetector = new PHIDetector({ sensitivity: this.sensitivity });
    this.ruleDb = new RuleDatabase(options.dbPath);
    this.ruleDb.initialize();
    this.regexCache = new RegexCache();
  }

  /**
   * Get parsed config for a rule, with memoization.
   */
  private getParsedConfig(rule: Rule): Record<string, unknown> | null {
    const cached = this.parsedConfigCache.get(rule.ruleId);
    if (cached !== undefined) return cached;

    try {
      const config = JSON.parse(rule.patternConfig) as Record<string, unknown>;
      this.parsedConfigCache.set(rule.ruleId, config);
      return config;
    } catch {
      return null;
    }
  }

  /**
   * Evaluate files against a compliance framework.
   */
  evaluate(
    paths: string[],
    framework = 'hipaa',
    options: { ignore?: string[]; maxFiles?: number; maxDepth?: number; timeoutMs?: number } = {},
  ): ScanResult {
    const startTime = Date.now();
    // Load .hipaalintignore from project root (first path)
    const projectIgnore = paths.length > 0 ? loadIgnoreFile(dirname(paths[0]!)) : [];
    const ignore = [...DEFAULT_IGNORE, ...projectIgnore, ...(options.ignore ?? [])];
    const maxFiles = options.maxFiles ?? 10000;
    const maxDepth = options.maxDepth ?? 50;
    const timeoutMs = options.timeoutMs ?? 60_000;

    // Collect files (with depth limit)
    const files = this.collectFiles(paths, ignore, maxFiles, maxDepth);
    const rules = this.ruleDb.getRulesByFramework(framework);

    // Evaluate each file
    const allFindings: ComplianceFinding[] = [];
    let filesSkipped = 0;
    let timedOut = false;
    const skipReasons = { binary: 0, tooLarge: 0, readError: 0 };

    for (const filePath of files) {
      // Timeout guard: stop scanning if time limit exceeded
      if (Date.now() - startTime > timeoutMs) {
        timedOut = true;
        break;
      }

      try {
        const content = readFileSync(filePath, 'utf-8');

        // Binary guard: skip files with null bytes
        if (isBinaryContent(content)) {
          filesSkipped++;
          skipReasons.binary++;
          continue;
        }

        // Size guard: skip files > 1MB
        if (content.length > 1_000_000) {
          filesSkipped++;
          skipReasons.tooLarge++;
          continue;
        }

        const findings = this.evaluateFile(filePath, content, rules);
        allFindings.push(...findings);
      } catch {
        filesSkipped++;
        skipReasons.readError++;
      }
    }

    const hasSkipReasons =
      skipReasons.binary > 0 || skipReasons.tooLarge > 0 || skipReasons.readError > 0;

    return {
      findings: this.deduplicateFindings(allFindings),
      filesScanned: files.length - filesSkipped,
      filesSkipped,
      rulesEvaluated: rules.length,
      scanDurationMs: Date.now() - startTime,
      timestamp: new Date().toISOString(),
      ...(timedOut && { timedOut: true }),
      ...(hasSkipReasons && { skipReasons }),
    };
  }

  /**
   * Evaluate a single file against rules.
   * Applies inline suppression comments (hipaalint-disable-*) to filter results.
   */
  private evaluateFile(filePath: string, content: string, rules: Rule[]): ComplianceFinding[] {
    const findings: ComplianceFinding[] = [];
    const lines = content.replace(/\r\n/g, '\n').split('\n');

    // Build suppression map from inline comments
    const suppressionMap = buildSuppressionMap(lines);

    // 1. Run PHI detector
    const phiFindings = this.phiDetector.detect(content, filePath);
    for (const phi of phiFindings) {
      const ruleId = `HIPAA-PHI-${phi.identifierType.toUpperCase()}`;

      // Check inline suppression
      if (isSuppressed(suppressionMap, phi.lineNumber - 1, ruleId)) continue;

      findings.push({
        ruleId,
        frameworkId: 'hipaa',
        severity:
          phi.confidence === 'high' ? 'critical' : phi.confidence === 'medium' ? 'high' : 'medium',
        category: 'phi_protection',
        title: `PHI Detected: ${phi.identifierType}`,
        description: `Potential ${phi.identifierType} found in ${phi.context}`,
        filePath,
        lineNumber: phi.lineNumber,
        columnNumber: phi.columnNumber,
        codeSnippet: this.sanitizeCodeSnippet(lines[phi.lineNumber - 1] ?? ''),
        citation: phi.citation,
        remediation: `Remove or encrypt the ${phi.identifierType} value. Use tokenized references instead.`,
        confidence: phi.confidence,
        context: phi.context,
        timestamp: new Date().toISOString(),
      });
    }

    // 2. Evaluate code pattern rules
    for (const rule of rules) {
      const config = this.getParsedConfig(rule);
      if (!config) continue;
      const ruleFindings = this.evaluateRule(filePath, content, lines, rule, config);

      // Filter out suppressed findings
      for (const finding of ruleFindings) {
        if (!isSuppressed(suppressionMap, finding.lineNumber - 1, finding.ruleId)) {
          findings.push(finding);
        }
      }
    }

    return findings;
  }

  /**
   * Evaluate a single rule against file content.
   */
  private evaluateRule(
    filePath: string,
    content: string,
    lines: string[],
    rule: Rule,
    config: Record<string, unknown>,
  ): ComplianceFinding[] {
    const findings: ComplianceFinding[] = [];

    switch (rule.patternType) {
      case 'code_pattern':
        findings.push(...this.evaluateCodePattern(filePath, content, lines, rule, config));
        break;
      case 'negative_pattern':
        findings.push(...this.evaluateNegativePattern(filePath, content, lines, rule, config));
        break;
      case 'config_pattern':
        findings.push(...this.evaluateConfigPattern(filePath, content, lines, rule, config));
        break;
      case 'import_pattern':
        findings.push(...this.evaluateImportPattern(filePath, content, lines, rule, config));
        break;
      case 'semantic_pattern':
        findings.push(...this.evaluateSemanticPattern(filePath, content, lines, rule, config));
        break;
    }

    return findings;
  }

  /**
   * Evaluate regex code patterns against file content.
   */
  private evaluateCodePattern(
    filePath: string,
    _content: string,
    lines: string[],
    rule: Rule,
    config: Record<string, unknown>,
  ): ComplianceFinding[] {
    const findings: ComplianceFinding[] = [];

    // Check variable name patterns
    if (config.variableNames && Array.isArray(config.variableNames)) {
      for (const varName of config.variableNames as string[]) {
        const flags = config.caseSensitive === false ? 'gi' : 'g';
        const regex = this.regexCache.get(`\\b${varName}\\b`, flags);
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]!;
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(line)) !== null) {
            // Skip if preceded by "encrypted", "hashed", etc.
            const before = line.substring(0, match.index).toLowerCase();
            if (/\b(encrypted|hashed|masked|redacted)\s*$/.test(before)) continue;

            findings.push(this.createFinding(rule, filePath, i + 1, match.index + 1, line));
          }
        }
      }
    }

    // Check regex patterns
    if (config.regex) {
      // Skip excluded files (match against filename, not full path)
      if (config.exclude && Array.isArray(config.exclude)) {
        const fileName = basename(filePath);
        const excluded = (config.exclude as string[]).some((pattern) => {
          const escaped = pattern.replace(/\./g, '\\.').replace(/\*/g, '.*');
          return this.regexCache.getSafe(`^${escaped}$`).test(fileName);
        });
        if (excluded) return findings;
      }

      const regex = this.regexCache.getSafe(config.regex as string, 'g');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        regex.lastIndex = 0;

        let match: RegExpExecArray | null;
        while ((match = regex.exec(line)) !== null) {
          // Skip if exclude patterns match
          if (config.excludePatterns && Array.isArray(config.excludePatterns)) {
            const excluded = (config.excludePatterns as string[]).some((p) =>
              this.regexCache.getSafe(p).test(line),
            );
            if (excluded) continue;
          }

          findings.push(this.createFinding(rule, filePath, i + 1, match.index + 1, line));
        }
      }
    }

    // Check function names
    if (config.functionNames && Array.isArray(config.functionNames)) {
      for (const funcName of config.functionNames as string[]) {
        const escaped = funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = this.regexCache.get(`\\b${escaped}\\s*\\(`, 'g');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]!;
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(line)) !== null) {
            findings.push(this.createFinding(rule, filePath, i + 1, match.index + 1, line));
          }
        }
      }
    }

    // Check general patterns array
    if (config.patterns && Array.isArray(config.patterns)) {
      for (const pattern of config.patterns as string[]) {
        const regex = this.regexCache.getSafe(pattern, 'g');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]!;
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(line)) !== null) {
            findings.push(this.createFinding(rule, filePath, i + 1, match.index + 1, line));
          }
        }
      }
    }

    return findings;
  }

  /**
   * Evaluate negative patterns (patterns that should NOT be present).
   */
  private evaluateNegativePattern(
    filePath: string,
    _content: string,
    lines: string[],
    rule: Rule,
    config: Record<string, unknown>,
  ): ComplianceFinding[] {
    const findings: ComplianceFinding[] = [];

    if (config.regex) {
      // Skip excluded files (match against filename, not full path)
      if (config.exclude && Array.isArray(config.exclude)) {
        const fileName = basename(filePath);
        const excluded = (config.exclude as string[]).some((pattern) => {
          const escaped = pattern.replace(/\./g, '\\.').replace(/\*/g, '.*');
          return this.regexCache.getSafe(`^${escaped}$`).test(fileName);
        });
        if (excluded) return findings;
      }

      const regex = this.regexCache.getSafe(config.regex as string, 'g');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        regex.lastIndex = 0;

        let match: RegExpExecArray | null;
        while ((match = regex.exec(line)) !== null) {
          findings.push(this.createFinding(rule, filePath, i + 1, match.index + 1, line));
        }
      }
    }

    return findings;
  }

  /**
   * Evaluate config file patterns.
   * Checks whether config files contain required settings.
   * If a file matches the checkFiles glob and lacks the required patterns,
   * a finding is raised indicating the missing configuration.
   */
  private evaluateConfigPattern(
    filePath: string,
    content: string,
    _lines: string[],
    rule: Rule,
    config: Record<string, unknown>,
  ): ComplianceFinding[] {
    // Only evaluate files that match the checkFiles globs
    if (!config.checkFiles || !Array.isArray(config.checkFiles)) return [];

    const fileName = basename(filePath);
    const matchesCheckFile = (config.checkFiles as string[]).some((glob) => {
      const pattern = glob.replace(/\./g, '\\.').replace(/\*/g, '.*');
      return this.regexCache.getSafe(`^${pattern}$`, 'i').test(fileName);
    });

    if (!matchesCheckFile) return [];

    // Collect all setting patterns to search for
    const settingPatterns: string[] = [];
    if (config.requiredSettings && Array.isArray(config.requiredSettings)) {
      settingPatterns.push(...(config.requiredSettings as string[]));
    }
    if (config.patterns && Array.isArray(config.patterns)) {
      settingPatterns.push(...(config.patterns as string[]));
    }

    if (settingPatterns.length === 0) return [];

    // Check if any of the required settings exist in the file content
    const lowerContent = content.toLowerCase();
    const hasAnySetting = settingPatterns.some((pattern) =>
      lowerContent.includes(pattern.toLowerCase()),
    );

    if (!hasAnySetting) {
      return [
        this.createFinding(
          rule,
          filePath,
          1,
          1,
          `Missing required configuration: ${settingPatterns.join(', ')}`,
        ),
      ];
    }

    return [];
  }

  /**
   * Evaluate import patterns (check for required security imports).
   */
  private evaluateImportPattern(
    filePath: string,
    content: string,
    _lines: string[],
    rule: Rule,
    config: Record<string, unknown>,
  ): ComplianceFinding[] {
    if (!config.requiredImports || !Array.isArray(config.requiredImports)) return [];

    // Only check relevant file types
    const ext = extname(filePath).toLowerCase();
    if (!['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py'].includes(ext)) return [];

    const lowerContent = content.toLowerCase();
    const hasAnyImport = (config.requiredImports as string[]).some((imp) =>
      lowerContent.includes(imp.toLowerCase()),
    );

    if (!hasAnyImport) {
      return [
        this.createFinding(
          rule,
          filePath,
          1,
          1,
          `Missing required import for: ${(config.requiredImports as string[]).join(', ')}`,
        ),
      ];
    }

    return [];
  }

  // ── AST Pattern Evaluation ──

  private static readonly CODE_EXTENSIONS = new Set([
    '.ts',
    '.tsx',
    '.js',
    '.jsx',
    '.mjs',
    '.cjs',
    '.py',
    '.java',
    '.go',
  ]);

  private static readonly PHI_VARIABLE_NAMES = [
    'patientName',
    'patient_name',
    'patientFirstName',
    'patient_first_name',
    'patientLastName',
    'patient_last_name',
    'ssn',
    'socialSecurityNumber',
    'social_security_number',
    'dob',
    'dateOfBirth',
    'date_of_birth',
    'birthDate',
    'birth_date',
    'mrn',
    'medicalRecordNumber',
    'medical_record_number',
    'patientEmail',
    'patient_email',
    'patientPhone',
    'patient_phone',
    'patientAddress',
    'patient_address',
    'diagnosis',
    'medication',
    'treatment',
    'prescription',
    'insuranceId',
    'insurance_id',
  ];

  private static readonly PHI_RESPONSE_FIELDS = [
    'ssn',
    'socialSecurity',
    'dateOfBirth',
    'dob',
    'birthDate',
    'diagnosis',
    'medicalRecord',
    'mrn',
    'address',
    'streetAddress',
    'patientName',
    'patient_name',
    'insurance',
    'medication',
    'treatment',
    'prescription',
  ];

  private evaluateSemanticPattern(
    filePath: string,
    _content: string,
    lines: string[],
    rule: Rule,
    config: Record<string, unknown>,
  ): ComplianceFinding[] {
    const ext = extname(filePath).toLowerCase();
    if (!RuleEvaluator.CODE_EXTENSIONS.has(ext)) return [];

    if (config.functionNames && config.checkArguments) {
      return this.detectPHIInLogStatements(filePath, lines, rule, config);
    }
    if (config.checkForPHIFields && config.apiContext) {
      return this.detectPHIInApiResponse(filePath, lines, rule);
    }
    if (config.checkThrowContent) {
      return this.detectPHIInErrorMessages(filePath, lines, rule);
    }
    if (config.routePatterns && config.requireMiddleware) {
      return this.detectMissingAuthMiddleware(filePath, lines, rule, config);
    }

    return [];
  }

  private detectPHIInLogStatements(
    filePath: string,
    lines: string[],
    rule: Rule,
    config: Record<string, unknown>,
  ): ComplianceFinding[] {
    const findings: ComplianceFinding[] = [];
    const functionNames = config.functionNames as string[];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      for (const funcName of functionNames) {
        const escaped = funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const callRegex = this.regexCache.get(`\\b${escaped}\\s*\\(`, 'g');
        callRegex.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = callRegex.exec(line)) !== null) {
          const argsText = this.extractCallArguments(lines, i, match.index + match[0].length);
          let found = false;

          for (const phiName of RuleEvaluator.PHI_VARIABLE_NAMES) {
            if (this.regexCache.get(`\\b${phiName}\\b`, 'i').test(argsText)) {
              findings.push(this.createFinding(rule, filePath, i + 1, match.index + 1, line));
              found = true;
              break;
            }
          }

          if (!found && this.containsInlinePHIPattern(argsText)) {
            findings.push(this.createFinding(rule, filePath, i + 1, match.index + 1, line));
          }
        }
      }
    }
    return findings;
  }

  private detectPHIInApiResponse(
    filePath: string,
    lines: string[],
    rule: Rule,
  ): ComplianceFinding[] {
    const findings: ComplianceFinding[] = [];
    const responsePatterns = [
      /\bres\.json\s*\(/g,
      /\bres\.send\s*\(/g,
      /\bresponse\.json\s*\(/g,
      /\bresponse\.send\s*\(/g,
      /\bjsonify\s*\(/g,
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      for (const pattern of responsePatterns) {
        const regex = this.regexCache.get(pattern.source, pattern.flags);
        regex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = regex.exec(line)) !== null) {
          const contextBlock = this.extractCallArguments(lines, i, match.index + match[0].length);
          for (const field of RuleEvaluator.PHI_RESPONSE_FIELDS) {
            if (this.regexCache.get(`\\b${field}\\b`, 'i').test(contextBlock)) {
              findings.push(this.createFinding(rule, filePath, i + 1, match.index + 1, line));
              break;
            }
          }
        }
      }
    }
    return findings;
  }

  private detectPHIInErrorMessages(
    filePath: string,
    lines: string[],
    rule: Rule,
  ): ComplianceFinding[] {
    const findings: ComplianceFinding[] = [];
    const catchRegex = /\b(catch|except)\s*[\s({]/;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      if (!catchRegex.test(line)) continue;

      const blockLines = this.extractBlock(lines, i, 20);

      for (let j = 0; j < blockLines.length; j++) {
        const blockLine = blockLines[j]!;
        if (!/\b(throw|raise)\b/.test(blockLine)) continue;

        for (const phiName of RuleEvaluator.PHI_VARIABLE_NAMES) {
          if (this.regexCache.get(`\\b${phiName}\\b`, 'i').test(blockLine)) {
            findings.push(this.createFinding(rule, filePath, i + j + 1, 1, blockLine));
            break;
          }
        }

        if (/\$\{[^}]*(patient|ssn|dob|mrn|name|phone|email|address)/i.test(blockLine)) {
          findings.push(this.createFinding(rule, filePath, i + j + 1, 1, blockLine));
        }
      }
    }
    return findings;
  }

  private detectMissingAuthMiddleware(
    filePath: string,
    lines: string[],
    rule: Rule,
    config: Record<string, unknown>,
  ): ComplianceFinding[] {
    const findings: ComplianceFinding[] = [];
    const routePatterns = config.routePatterns as string[];
    const requiredMiddleware = config.requireMiddleware as string[];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      for (const routePattern of routePatterns) {
        const escaped = routePattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const routeRegex = this.regexCache.get(`\\b${escaped}\\s*\\(`, 'g');
        routeRegex.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = routeRegex.exec(line)) !== null) {
          const argsText = this.extractCallArguments(lines, i, match.index + match[0].length);
          const hasAuth = requiredMiddleware.some((mw) =>
            this.regexCache.get(`\\b${mw}\\b`, 'i').test(argsText),
          );

          if (!hasAuth) {
            findings.push(this.createFinding(rule, filePath, i + 1, match.index + 1, line));
          }
        }
      }
    }
    return findings;
  }

  // ── AST Pattern Helpers ──

  private extractCallArguments(lines: string[], startLine: number, startCol: number): string {
    let depth = 1;
    let result = '';
    const firstLine = lines[startLine]!;
    result += firstLine.substring(startCol);

    // Check if paren closes on same line
    for (let c = startCol; c < firstLine.length; c++) {
      const ch = firstLine[c]!;
      if (ch === '(') depth++;
      else if (ch === ')') depth--;
      if (depth === 0) return firstLine.substring(startCol, c);
    }

    // Look ahead up to 10 lines
    const maxLookahead = Math.min(startLine + 10, lines.length - 1);
    for (let i = startLine + 1; i <= maxLookahead; i++) {
      const line = lines[i]!;
      result += '\n' + line;
      for (const ch of line) {
        if (ch === '(') depth++;
        else if (ch === ')') depth--;
        if (depth === 0) return result;
      }
    }

    return result;
  }

  private extractBlock(lines: string[], startLine: number, maxLines: number): string[] {
    const block: string[] = [];
    let depth = 0;
    let foundOpen = false;
    const limit = Math.min(startLine + maxLines, lines.length);

    for (let i = startLine; i < limit; i++) {
      const line = lines[i]!;
      block.push(line);

      for (const ch of line) {
        if (ch === '{') {
          depth++;
          foundOpen = true;
        } else if (ch === '}' && foundOpen) {
          depth--;
        }
      }

      if (foundOpen && depth <= 0) break;
    }

    return block;
  }

  private containsInlinePHIPattern(text: string): boolean {
    // SSN pattern in string
    if (/\d{3}-\d{2}-\d{4}/.test(text)) return true;
    // Template interpolation with PHI variable names
    if (/\$\{[^}]*(patient|ssn|dob|mrn|diagnosis|medication)/i.test(text)) return true;
    return false;
  }

  /**
   * Create a ComplianceFinding from a rule match.
   */
  private createFinding(
    rule: Rule,
    filePath: string,
    lineNumber: number,
    columnNumber: number,
    line: string,
  ): ComplianceFinding {
    return {
      ruleId: rule.ruleId,
      frameworkId: 'hipaa',
      severity: rule.severity,
      category: rule.category,
      title: rule.title,
      description: rule.description,
      filePath,
      lineNumber,
      columnNumber,
      codeSnippet: this.sanitizeCodeSnippet(line),
      citation: rule.citation,
      remediation: rule.remediation,
      confidence: 'high',
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Sanitize code snippets to prevent PHI leakage in reports.
   */
  private sanitizeCodeSnippet(line: string): string {
    let sanitized = line.trim();
    // Redact known PHI patterns to prevent leakage in reports
    sanitized = sanitized.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED-SSN]');
    sanitized = sanitized.replace(
      /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
      '[REDACTED-EMAIL]',
    );
    sanitized = sanitized.replace(/\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g, '[REDACTED-PHONE]');
    sanitized = sanitized.replace(/\bMRN[-_:# ]?\d{4,12}\b/gi, '[REDACTED-MRN]');
    // Truncate long lines
    if (sanitized.length > 200) {
      sanitized = sanitized.substring(0, 200) + '...';
    }
    return sanitized;
  }

  /**
   * Collect all scannable files from paths.
   */
  private collectFiles(
    paths: string[],
    ignore: string[],
    maxFiles: number,
    maxDepth: number,
  ): string[] {
    const files: string[] = [];

    // Pre-compile ignore patterns once
    const compiledIgnore: Array<{ exact: string } | { regex: RegExp }> = ignore.map((pattern) =>
      pattern.includes('*')
        ? { regex: new RegExp(pattern.replace(/\*/g, '.*')) }
        : { exact: pattern },
    );

    for (const scanPath of paths) {
      const validatedPath = validateScanPath(scanPath);
      this.walkDirectory(validatedPath, compiledIgnore, files, maxFiles, maxDepth, 0);
      if (files.length >= maxFiles) break;
    }

    return files.slice(0, maxFiles);
  }

  /**
   * Check if a name matches any compiled ignore pattern.
   */
  private isIgnored(name: string, patterns: Array<{ exact: string } | { regex: RegExp }>): boolean {
    for (const p of patterns) {
      if ('exact' in p) {
        if (name === p.exact) return true;
      } else {
        if (p.regex.test(name)) return true;
      }
    }
    return false;
  }

  /**
   * Recursively walk a directory using Dirent for efficient type checking.
   * Respects maxDepth to prevent unbounded traversal.
   */
  private walkDirectory(
    dir: string,
    compiledIgnore: Array<{ exact: string } | { regex: RegExp }>,
    files: string[],
    maxFiles: number,
    maxDepth: number,
    currentDepth: number,
  ): void {
    if (files.length >= maxFiles) return;
    if (currentDepth > maxDepth) return; // Depth limit reached

    try {
      const stat = lstatSync(dir);
      if (stat.isSymbolicLink()) return; // Skip symlinks
      if (stat.isFile()) {
        if (
          SUPPORTED_EXTENSIONS.has(extname(dir).toLowerCase()) ||
          isSupportedFilename(basename(dir))
        ) {
          files.push(dir);
        }
        return;
      }
    } catch {
      return;
    }

    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (files.length >= maxFiles) break;
        if (this.isIgnored(entry.name, compiledIgnore)) continue;

        // Skip symbolic links to prevent directory escape
        if (entry.isSymbolicLink()) continue;

        const fullPath = join(dir, entry.name);

        if (entry.isDirectory()) {
          this.walkDirectory(fullPath, compiledIgnore, files, maxFiles, maxDepth, currentDepth + 1);
        } else if (
          entry.isFile() &&
          (SUPPORTED_EXTENSIONS.has(extname(entry.name).toLowerCase()) ||
            isSupportedFilename(entry.name))
        ) {
          files.push(fullPath);
        }
      }
    } catch {
      // Skip inaccessible directories
    }
  }

  /**
   * Deduplicate findings by location.
   */
  private deduplicateFindings(findings: ComplianceFinding[]): ComplianceFinding[] {
    const seen = new Set<string>();
    return findings.filter((f) => {
      const key = `${f.ruleId}:${f.filePath}:${f.lineNumber}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  /**
   * Get the rule database instance.
   */
  getRuleDatabase(): RuleDatabase {
    return this.ruleDb;
  }

  /**
   * Close the database connection.
   */
  close(): void {
    this.ruleDb.close();
  }
}
