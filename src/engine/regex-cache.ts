// ──────────────────────────────────────────────────
// Regex Compilation Cache
// ──────────────────────────────────────────────────

import { isReDoSVulnerable } from '../security/regex-safety.js';

/**
 * A cache for compiled RegExp objects, keyed by (pattern, flags).
 * Stateful regexes (global/sticky) have lastIndex reset before reuse.
 *
 * Uses a null-byte separator in the key since \0 cannot appear
 * in regex patterns or flags, preventing key collisions.
 */
export class RegexCache {
  private cache = new Map<string, RegExp>();

  /**
   * Get or compile a RegExp. Resets lastIndex to 0 for global/sticky regexes.
   */
  get(pattern: string, flags?: string): RegExp {
    const key = `${pattern}\0${flags ?? ''}`;
    let regex = this.cache.get(key);
    if (!regex) {
      regex = new RegExp(pattern, flags);
      this.cache.set(key, regex);
    }
    regex.lastIndex = 0;
    return regex;
  }

  /**
   * Get or compile with ReDoS safety check.
   * Returns a never-matching regex (/(?!)/) for dangerous or invalid patterns.
   */
  getSafe(pattern: string, flags?: string): RegExp {
    const key = `safe\0${pattern}\0${flags ?? ''}`;
    let regex = this.cache.get(key);
    if (!regex) {
      if (isReDoSVulnerable(pattern)) {
        regex = /(?!)/;
      } else {
        try {
          regex = new RegExp(pattern, flags);
        } catch {
          regex = /(?!)/;
        }
      }
      this.cache.set(key, regex);
    }
    regex.lastIndex = 0;
    return regex;
  }

  /** Number of cached entries. */
  get size(): number {
    return this.cache.size;
  }

  /** Clear the cache. */
  clear(): void {
    this.cache.clear();
  }
}
