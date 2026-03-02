import { resolve, normalize, sep } from 'path';
import { existsSync, lstatSync, mkdirSync } from 'fs';

// ──────────────────────────────────────────────────
// Security Error
// ──────────────────────────────────────────────────

export class SecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecurityError';
  }
}

// ──────────────────────────────────────────────────
// Blocked system directories
// ──────────────────────────────────────────────────

const BLOCKED_OUTPUT_DIRS = [
  // Unix
  '/etc',
  '/sys',
  '/proc',
  '/dev',
  '/boot',
  '/sbin',
  '/usr/sbin',
  '/var/run',
  // Windows (case-insensitive comparison used)
  'c:\\windows',
  'c:\\program files',
  'c:\\program files (x86)',
  'c:\\programdata',
];

// ──────────────────────────────────────────────────
// Path Validation
// ──────────────────────────────────────────────────

/**
 * Validate and resolve a path for scanning.
 * Rejects null bytes and verifies the path exists.
 */
export function validateScanPath(inputPath: string): string {
  if (!inputPath || inputPath.trim().length === 0) {
    throw new SecurityError('Path must not be empty');
  }

  if (inputPath.includes('\0')) {
    throw new SecurityError('Null byte detected in path');
  }

  const resolved = resolve(normalize(inputPath));

  if (!existsSync(resolved)) {
    throw new SecurityError(`Path does not exist: ${resolved}`);
  }

  return resolved;
}

/**
 * Validate an output directory for report generation.
 * Rejects null bytes, system directories, and creates dir if missing.
 */
export function validateOutputDirectory(outputDir: string): string {
  if (!outputDir || outputDir.trim().length === 0) {
    throw new SecurityError('Output directory must not be empty');
  }

  if (outputDir.includes('\0')) {
    throw new SecurityError('Null byte detected in output path');
  }

  const resolved = resolve(normalize(outputDir));
  const lowerResolved = resolved.toLowerCase();

  for (const blocked of BLOCKED_OUTPUT_DIRS) {
    if (lowerResolved === blocked || lowerResolved.startsWith(blocked + sep)) {
      throw new SecurityError(`Cannot write to system directory: ${resolved}`);
    }
    // Handle forward-slash variants on Windows
    const blockedFwd = blocked.replace(/\\/g, '/');
    const lowerFwd = lowerResolved.replace(/\\/g, '/');
    if (lowerFwd === blockedFwd || lowerFwd.startsWith(blockedFwd + '/')) {
      throw new SecurityError(`Cannot write to system directory: ${resolved}`);
    }
  }

  if (!existsSync(resolved)) {
    try {
      mkdirSync(resolved, { recursive: true });
    } catch {
      throw new SecurityError(`Cannot create output directory: ${resolved}`);
    }
  }

  return resolved;
}

/**
 * Check if a path is a symbolic link without following it.
 */
export function isSymlink(filePath: string): boolean {
  try {
    return lstatSync(filePath).isSymbolicLink();
  } catch {
    return false;
  }
}

/**
 * Sanitize a filename by stripping path separators and null bytes.
 */
export function sanitizeFilename(name: string): string {
  return name.replace(/[\0/\\]/g, '_');
}
