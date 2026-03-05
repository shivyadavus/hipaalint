import type { PHIFinding, PHIIdentifierType } from './types.js';

// ──────────────────────────────────────────────────
// PHI Pattern Definitions
// ──────────────────────────────────────────────────

interface PHIPattern {
  type: PHIIdentifierType;
  regex: RegExp;
  confidence: 'high' | 'medium' | 'low';
  citation: string;
  excludePatterns?: RegExp[];
}

const PHI_PATTERNS: PHIPattern[] = [
  // 1. SSN
  {
    type: 'ssn',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    confidence: 'high',
    citation: '45 CFR §164.514(a) — De-identification',
    excludePatterns: [/\/\/.*\d{3}-\d{2}-\d{4}/, /\*.*\d{3}-\d{2}-\d{4}/],
  },
  // 2. Email
  {
    type: 'email',
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    confidence: 'medium',
    citation: '45 CFR §164.514(b)(2)(i)(C) — Electronic mail addresses',
    excludePatterns: [/@example\.com/i, /@test\.com/i, /@localhost/i, /@placeholder/i],
  },
  // 3. Phone numbers
  {
    type: 'phone',
    regex: /\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g,
    confidence: 'medium',
    citation: '45 CFR §164.514(b)(2)(i)(D) — Telephone numbers',
  },
  // 4. IP addresses
  {
    type: 'ip_address',
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    confidence: 'medium',
    citation: '45 CFR §164.514(b)(2)(i)(O) — Internet Protocol address numbers',
    excludePatterns: [/127\.0\.0\.1/, /0\.0\.0\.0/, /localhost/],
  },
  // 5. Dates of birth
  {
    type: 'date_of_birth',
    regex: /\b(?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])[-/](?:19|20)\d{2}\b/g,
    confidence: 'medium',
    citation: '45 CFR §164.514(b)(2)(i)(B) — Dates related to individual',
  },
  // 6. Medical record numbers
  {
    type: 'medical_record_number',
    regex: /\bMRN[-_:# ]?\d{4,12}\b/gi,
    confidence: 'high',
    citation: '45 CFR §164.514(b)(2)(i)(F) — Medical record numbers',
  },
  // 7. URLs with potential PII
  {
    type: 'url',
    regex: /https?:\/\/[^\s'"`)]+patient[^\s'"`)]+/gi,
    confidence: 'low',
    citation: '45 CFR §164.514(b)(2)(i)(M) — Web URLs',
  },
  // 8. Fax numbers (same as phone but in fax context)
  {
    type: 'fax',
    regex: /fax[:\s]+\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/gi,
    confidence: 'high',
    citation: '45 CFR §164.514(b)(2)(i)(E) — Fax numbers',
  },
];

// Variable names that suggest PHI
const PHI_VARIABLE_PATTERNS: Array<{
  type: PHIIdentifierType;
  names: string[];
  confidence: 'high' | 'medium' | 'low';
  citation: string;
}> = [
  {
    type: 'name',
    names: [
      'patientName',
      'patient_name',
      'patientFirstName',
      'patient_first_name',
      'patientLastName',
      'patient_last_name',
      'patientFullName',
      'patient_full_name',
    ],
    confidence: 'medium',
    citation: '45 CFR §164.514(b)(2)(i)(A) — Names',
  },
  {
    type: 'ssn',
    names: [
      'ssn',
      'socialSecurityNumber',
      'social_security_number',
      'patientSSN',
      'patient_ssn',
      'socialSecurity',
    ],
    confidence: 'high',
    citation: '45 CFR §164.514(a) — De-identification',
  },
  {
    type: 'date_of_birth',
    names: [
      'dob',
      'dateOfBirth',
      'date_of_birth',
      'birthDate',
      'birth_date',
      'patientDOB',
      'patient_dob',
      'birthday',
    ],
    confidence: 'medium',
    citation: '45 CFR §164.514(b)(2)(i)(B) — Dates related to individual',
  },
  {
    type: 'medical_record_number',
    names: [
      'mrn',
      'medicalRecordNumber',
      'medical_record_number',
      'medicalRecordNum',
      'medical_record_num',
      'chartNumber',
      'chart_number',
    ],
    confidence: 'high',
    citation: '45 CFR §164.514(b)(2)(i)(F) — Medical record numbers',
  },
  {
    type: 'health_plan_beneficiary',
    names: [
      'insuranceId',
      'insurance_id',
      'healthPlanId',
      'health_plan_id',
      'beneficiaryNumber',
      'beneficiary_number',
      'memberId',
      'member_id',
    ],
    confidence: 'medium',
    citation: '45 CFR §164.514(b)(2)(i)(G) — Health plan beneficiary numbers',
  },
  {
    type: 'account_number',
    names: [
      'accountNumber',
      'account_number',
      'patientAccount',
      'patient_account',
      'billingAccount',
      'billing_account',
    ],
    confidence: 'low',
    citation: '45 CFR §164.514(b)(2)(i)(H) — Account numbers',
  },
  {
    type: 'phone',
    names: [
      'patientPhone',
      'patient_phone',
      'patientMobile',
      'patient_mobile',
      'contactPhone',
      'contact_phone',
    ],
    confidence: 'medium',
    citation: '45 CFR §164.514(b)(2)(i)(D) — Telephone numbers',
  },
  {
    type: 'email',
    names: ['patientEmail', 'patient_email', 'contactEmail', 'contact_email'],
    confidence: 'medium',
    citation: '45 CFR §164.514(b)(2)(i)(C) — Electronic mail addresses',
  },
  {
    type: 'address',
    names: [
      'patientAddress',
      'patient_address',
      'homeAddress',
      'home_address',
      'streetAddress',
      'street_address',
      'patientStreet',
      'patient_street',
    ],
    confidence: 'medium',
    citation: '45 CFR §164.514(b)(2)(i)(L) — Geographic data',
  },
  {
    type: 'device_identifier',
    names: [
      'deviceSerial',
      'device_serial',
      'deviceId',
      'device_identifier',
      'serialNumber',
      'serial_number',
    ],
    confidence: 'low',
    citation: '45 CFR §164.514(b)(2)(i)(K) — Device identifiers',
  },
];

// Pre-compiled variable name regexes (computed once at module load)
const COMPILED_VAR_PATTERNS: Array<{
  type: PHIIdentifierType;
  regexes: Array<{ name: string; regex: RegExp }>;
  confidence: 'high' | 'medium' | 'low';
  citation: string;
}> = PHI_VARIABLE_PATTERNS.map((vp) => ({
  type: vp.type,
  regexes: vp.names.map((name) => ({
    name,
    regex: new RegExp(`\\b${name}\\b`, 'g'),
  })),
  confidence: vp.confidence,
  citation: vp.citation,
}));

// Log function names to check for PHI in arguments
const LOG_FUNCTIONS = new Set([
  'console.log',
  'console.error',
  'console.warn',
  'console.info',
  'console.debug',
  'logger.info',
  'logger.warn',
  'logger.error',
  'logger.debug',
  'logger.log',
  'log.info',
  'log.warn',
  'log.error',
  'log.debug',
  'print',
  'println',
  'logging.info',
  'logging.warning',
  'logging.error',
  'logging.debug',
  'console.trace',
]);

// ──────────────────────────────────────────────────
// PHI Detection Context
// ──────────────────────────────────────────────────

type PHIContext = PHIFinding['context'];

function detectContext(line: string): PHIContext {
  const lower = line.toLowerCase();
  if (LOG_FUNCTIONS.has(lower.trim().split('(')[0]?.trim() ?? '')) return 'log_statement';
  if (/\b(console|logger|log|logging|print)\b/.test(lower)) return 'log_statement';
  if (/\b(catch|except|rescue)\b/.test(lower)) return 'error_handler';
  if (/\b(const|let|var|val|def)\b/.test(lower)) return 'variable_declaration';
  if (/\b(res\.json|res\.send|response\.send|return\s+\{|jsonify)\b/.test(lower))
    return 'api_response';
  if (/\b(SELECT|INSERT|UPDATE|DELETE|query|execute)\b/i.test(lower)) return 'database_query';
  if (/\b(test|spec|describe|it\(|expect)\b/.test(lower)) return 'test_fixture';
  if (/^\s*(\/\/|#|\/\*|\*|""")/.test(line)) return 'comment';
  if (/\.(env|config|json|yaml|yml|toml)$/.test(lower)) return 'config_file';
  return 'other';
}

function redactMatch(text: string): string {
  if (text.length <= 4) return '***';
  return text.substring(0, 2) + '*'.repeat(text.length - 4) + text.substring(text.length - 2);
}

// ──────────────────────────────────────────────────
// Main Detector
// ──────────────────────────────────────────────────

export interface PHIDetectorOptions {
  sensitivity?: 'strict' | 'balanced' | 'relaxed';
  excludeTestFiles?: boolean;
}

export class PHIDetector {
  private sensitivity: 'strict' | 'balanced' | 'relaxed';
  private excludeTestFiles: boolean;

  constructor(options: PHIDetectorOptions = {}) {
    this.sensitivity = options.sensitivity ?? 'balanced';
    this.excludeTestFiles = options.excludeTestFiles ?? this.sensitivity === 'relaxed';
  }

  /**
   * Detect PHI in source code content.
   */
  detect(content: string, filePath: string): PHIFinding[] {
    const findings: PHIFinding[] = [];

    // Skip test files in relaxed mode
    if (this.excludeTestFiles && this.isTestFile(filePath)) {
      return findings;
    }

    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      const lineNumber = i + 1;
      const context = detectContext(line);

      // 1. Check regex patterns
      for (const pattern of PHI_PATTERNS) {
        if (this.shouldSkipPattern(pattern, context)) continue;

        pattern.regex.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = pattern.regex.exec(line)) !== null) {
          if (this.isExcluded(match[0], line, pattern.excludePatterns)) continue;

          findings.push({
            identifierType: pattern.type,
            filePath,
            lineNumber,
            columnNumber: match.index + 1,
            matchedText: redactMatch(match[0]),
            context,
            confidence: this.adjustConfidence(pattern.confidence, context),
            citation: pattern.citation,
          });
        }
      }

      // 2. Check variable name patterns (pre-compiled)
      for (const varPattern of COMPILED_VAR_PATTERNS) {
        for (const { name, regex: nameRegex } of varPattern.regexes) {
          nameRegex.lastIndex = 0;
          let match: RegExpExecArray | null;

          while ((match = nameRegex.exec(line)) !== null) {
            // Skip if the variable name is prefixed with "encrypted" or "hashed"
            const precedingText = line.substring(0, match.index).toLowerCase();
            if (/\b(encrypted|hashed|masked|redacted|scrubbed|sanitized)\s*$/.test(precedingText)) {
              continue;
            }

            findings.push({
              identifierType: varPattern.type,
              filePath,
              lineNumber,
              columnNumber: match.index + 1,
              matchedText: name,
              context,
              confidence: this.adjustConfidence(varPattern.confidence, context),
              citation: varPattern.citation,
            });
          }
        }
      }
    }

    return this.deduplicateFindings(findings);
  }

  /**
   * Quick check if a string contains potential PHI patterns.
   */
  containsPHI(text: string): boolean {
    for (const pattern of PHI_PATTERNS) {
      pattern.regex.lastIndex = 0;
      if (pattern.regex.test(text)) return true;
    }
    return false;
  }

  private shouldSkipPattern(pattern: PHIPattern, context: PHIContext): boolean {
    // In relaxed mode, skip low-confidence patterns in non-critical contexts
    if (this.sensitivity === 'relaxed') {
      if (pattern.confidence === 'low') return true;
      if (context === 'comment' || context === 'test_fixture') return true;
    }
    // In balanced mode, skip low-confidence in comments
    if (this.sensitivity === 'balanced' && pattern.confidence === 'low' && context === 'comment') {
      return true;
    }
    return false;
  }

  private isExcluded(matchedText: string, line: string, excludePatterns?: RegExp[]): boolean {
    if (!excludePatterns) return false;
    for (const exclude of excludePatterns) {
      if (exclude.test(matchedText) || exclude.test(line)) return true;
    }
    return false;
  }

  private adjustConfidence(
    base: 'high' | 'medium' | 'low',
    context: PHIContext,
  ): 'high' | 'medium' | 'low' {
    // PHI in logs or API responses is higher confidence
    if (context === 'log_statement' || context === 'api_response') {
      if (base === 'low') return 'medium';
      if (base === 'medium') return 'high';
    }
    // PHI in comments is lower confidence
    if (context === 'comment') {
      if (base === 'high') return 'medium';
      if (base === 'medium') return 'low';
    }
    return base;
  }

  private isTestFile(filePath: string): boolean {
    return (
      /\.(test|spec|__test__|_test)\.(ts|js|py|java|go)$/.test(filePath) ||
      /\/(tests?|__tests__|spec)\//i.test(filePath)
    );
  }

  private deduplicateFindings(findings: PHIFinding[]): PHIFinding[] {
    const seen = new Set<string>();
    return findings.filter((f) => {
      const key = `${f.filePath}:${f.lineNumber}:${f.columnNumber}:${f.identifierType}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
}
