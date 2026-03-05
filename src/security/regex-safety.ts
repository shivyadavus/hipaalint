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
 * Module-level cache for compiled safe regexes.
 * Key format: pattern + \0 + flags (null byte cannot appear in patterns/flags).
 */
const safeRegexCache = new Map<string, RegExp>();

/**
 * Create a RegExp with static safety checks and caching.
 * If the pattern is detected as potentially dangerous, returns a regex
 * that never matches (defensive fallback).
 * Cached regexes have lastIndex reset to 0 on each retrieval.
 *
 * @param pattern - The regex pattern string
 * @param flags - Optional regex flags (e.g. 'g', 'i')
 * @returns A compiled RegExp instance
 */
export function createSafeRegex(pattern: string, flags?: string): RegExp {
  const key = `${pattern}\0${flags ?? ''}`;
  const cached = safeRegexCache.get(key);
  if (cached) {
    cached.lastIndex = 0;
    return cached;
  }

  let regex: RegExp;
  if (isReDoSVulnerable(pattern)) {
    // Return a regex that matches nothing — safe fallback
    regex = /(?!)/;
  } else {
    try {
      regex = new RegExp(pattern, flags);
    } catch {
      // Invalid regex syntax — return non-matching regex
      regex = /(?!)/;
    }
  }

  safeRegexCache.set(key, regex);
  return regex;
}
