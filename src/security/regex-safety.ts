// ──────────────────────────────────────────────────
// ReDoS Protection
// ──────────────────────────────────────────────────

/**
 * Patterns that indicate potential catastrophic backtracking.
 * Matches nested quantifiers like (a+)+, (a*)+, (a+)*, (a|a)+
 */
const DANGEROUS_PATTERNS = [
  /\(.+[+*]\)\s*[+*]/, // nested quantifiers: (x+)+, (x*)+, etc.
  /\(.+\|.+\)\s*[+*]/, // alternation with quantifier: (a|b)+
];

/**
 * Check whether a regex pattern contains potentially dangerous
 * constructs that could cause catastrophic backtracking (ReDoS).
 */
export function isReDoSVulnerable(pattern: string): boolean {
  return DANGEROUS_PATTERNS.some((check) => check.test(pattern));
}

/**
 * Create a RegExp with static safety checks.
 * If the pattern is detected as potentially dangerous, returns a regex
 * that never matches (defensive fallback).
 *
 * @param pattern - The regex pattern string
 * @param flags - Optional regex flags (e.g. 'g', 'i')
 * @returns A compiled RegExp instance
 */
export function createSafeRegex(pattern: string, flags?: string): RegExp {
  if (isReDoSVulnerable(pattern)) {
    // Return a regex that matches nothing — safe fallback
    return /(?!)/;
  }

  try {
    return new RegExp(pattern, flags);
  } catch {
    // Invalid regex syntax — return non-matching regex
    return /(?!)/;
  }
}
