/**
 * AST-based Taint Tracker (Foundation)
 *
 * Provides single-file, 1-level taint tracking for PHI variables.
 * Uses regex-based lightweight AST analysis (no tree-sitter dependency at runtime
 * to avoid WASM loading complexity in CLI context).
 *
 * Detects patterns like:
 *   const x = ssn;          // x is tainted
 *   console.log(x);         // flagged: tainted variable in log
 *   res.json({ data: x });  // flagged: tainted variable in response
 */

import type { ComplianceFinding, Rule } from './types.js';

// PHI-related variable names that act as taint sources
const TAINT_SOURCES = new Set([
  'ssn',
  'socialsecuritynumber',
  'social_security_number',
  'patientname',
  'patient_name',
  'patientfirstname',
  'patientlastname',
  'firstname',
  'lastname',
  'dateofbirth',
  'date_of_birth',
  'dob',
  'patientdob',
  'mrn',
  'medicalrecordnumber',
  'medical_record_number',
  'diagnosis',
  'medication',
  'prescription',
  'healthplanid',
  'health_plan_id',
  'patientemail',
  'patient_email',
  'patientphone',
  'patient_phone',
  'patientaddress',
  'patient_address',
]);

// Sink functions where tainted data is dangerous
const SINK_PATTERNS = [
  // Logging
  /\b(console\.(log|error|warn|info|debug)|logger\.(info|warn|error|debug)|print|logging\.(info|warning|error|debug))\s*\(/,
  // HTTP responses
  /\b(res\.(json|send|write|end)|response\.(json|send|write|end))\s*\(/,
  // Error throwing
  /\b(throw\s+new\s+Error)\s*\(/,
];

interface TaintEntry {
  variableName: string;
  sourceName: string;
  lineNumber: number;
}

/**
 * Analyze a file for taint propagation of PHI variables.
 * Returns findings where tainted variables flow into sinks.
 */
export function analyzeTaint(filePath: string, content: string, rule: Rule): ComplianceFinding[] {
  const lines = content.split('\n');
  const taintMap = buildTaintMap(lines);

  if (taintMap.size === 0) return [];

  return detectTaintedSinks(filePath, lines, taintMap, rule);
}

/**
 * Build a map of tainted variable names from assignment statements.
 * Tracks 1 level: `const x = ssn;` → x is tainted.
 */
function buildTaintMap(lines: string[]): Map<string, TaintEntry> {
  const taintMap = new Map<string, TaintEntry>();

  // Pattern: const/let/var x = <taint_source>
  const assignmentPattern =
    /\b(?:const|let|var)\s+(\w+)\s*=\s*(?:(?:req\.(?:body|params|query)\.)?(\w+)|(\w+))\s*[;,]/;

  // Pattern: destructuring const { x } = obj (where obj contains taint)
  const destructurePattern = /\b(?:const|let|var)\s+\{\s*([^}]+)\}\s*=\s*(\w+)/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    // Check simple assignments
    const assignMatch = assignmentPattern.exec(line);
    if (assignMatch) {
      const varName = assignMatch[1]!;
      const rhs = (assignMatch[2] || assignMatch[3] || '').toLowerCase();

      if (TAINT_SOURCES.has(rhs) || taintMap.has(rhs)) {
        taintMap.set(varName.toLowerCase(), {
          variableName: varName,
          sourceName: rhs,
          lineNumber: i + 1,
        });
      }
    }

    // Check function parameters with PHI-like names
    const paramPattern =
      /\b(?:function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?)\s*\(([^)]+)\)/;
    const paramMatch = paramPattern.exec(line);
    if (paramMatch) {
      const params = paramMatch[1]!.split(',').map((p) =>
        p
          .trim()
          .split(/[:\s=]/)[0]!
          .trim(),
      );
      for (const param of params) {
        if (TAINT_SOURCES.has(param.toLowerCase())) {
          taintMap.set(param.toLowerCase(), {
            variableName: param,
            sourceName: param,
            lineNumber: i + 1,
          });
        }
      }
    }

    // Check destructuring
    const destructMatch = destructurePattern.exec(line);
    if (destructMatch) {
      const fields = destructMatch[1]!.split(',').map((f) => f.trim().split(/[:\s]/)[0]!.trim());
      for (const field of fields) {
        if (TAINT_SOURCES.has(field.toLowerCase())) {
          taintMap.set(field.toLowerCase(), {
            variableName: field,
            sourceName: field,
            lineNumber: i + 1,
          });
        }
      }
    }
  }

  return taintMap;
}

/**
 * Detect tainted variables being passed to sink functions.
 */
function detectTaintedSinks(
  filePath: string,
  lines: string[],
  taintMap: Map<string, TaintEntry>,
  rule: Rule,
): ComplianceFinding[] {
  const findings: ComplianceFinding[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    // Check if line contains a sink
    const isSink = SINK_PATTERNS.some((p) => p.test(line));
    if (!isSink) continue;

    // Check if any tainted variable appears in the sink call
    for (const [, entry] of taintMap) {
      // Build a regex to match the tainted variable name as a word boundary
      const varPattern = new RegExp(`\\b${escapeRegex(entry.variableName)}\\b`);
      if (varPattern.test(line)) {
        findings.push({
          ruleId: rule.ruleId,
          frameworkId: 'hipaa',
          severity: rule.severity,
          category: rule.category,
          title: `Tainted PHI variable '${entry.variableName}' used in sink`,
          description: `Variable '${entry.variableName}' (tainted from '${entry.sourceName}' at line ${entry.lineNumber}) flows into a logging/response function. ${rule.description}`,
          filePath,
          lineNumber: i + 1,
          columnNumber: 1,
          codeSnippet: sanitizeLine(line),
          citation: rule.citation,
          remediation: rule.remediation,
          confidence: 'medium',
          context: determineSinkContext(line),
          timestamp: new Date().toISOString(),
        });
        break; // One finding per line
      }
    }
  }

  return findings;
}

function determineSinkContext(
  line: string,
): 'log_statement' | 'api_response' | 'error_handler' | 'other' {
  if (/\b(console\.|logger\.|print|logging\.)/.test(line)) return 'log_statement';
  if (/\b(res\.|response\.)/.test(line)) return 'api_response';
  if (/\bthrow\b/.test(line)) return 'error_handler';
  return 'other';
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function sanitizeLine(line: string): string {
  let s = line.trim();
  s = s.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED-SSN]');
  s = s.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[REDACTED-EMAIL]');
  if (s.length > 200) s = s.substring(0, 200) + '...';
  return s;
}
