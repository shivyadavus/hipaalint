import { describe, it, expect } from 'vitest';
import { createSafeRegex, isReDoSVulnerable } from '../../src/security/regex-safety.js';

describe('Regex Safety', () => {
  describe('isReDoSVulnerable', () => {
    it('should detect nested quantifiers (a+)+', () => {
      expect(isReDoSVulnerable('(a+)+')).toBe(true);
    });

    it('should detect nested quantifiers (a*)*', () => {
      expect(isReDoSVulnerable('(a*)*')).toBe(true);
    });

    it('should detect nested quantifiers (a+)*', () => {
      expect(isReDoSVulnerable('(a+)*')).toBe(true);
    });

    it('should detect alternation with quantifier (a|b)+', () => {
      expect(isReDoSVulnerable('(a|b)+')).toBe(true);
    });

    it('should not flag simple patterns', () => {
      expect(isReDoSVulnerable('^[a-z]+$')).toBe(false);
    });

    it('should not flag basic quantifiers', () => {
      expect(isReDoSVulnerable('\\d{3}-\\d{2}-\\d{4}')).toBe(false);
    });

    it('should not flag character classes with quantifiers', () => {
      expect(isReDoSVulnerable('[A-Za-z0-9]+')).toBe(false);
    });
  });

  describe('createSafeRegex', () => {
    it('should compile safe patterns normally', () => {
      const regex = createSafeRegex('^hello$');
      expect(regex.test('hello')).toBe(true);
      expect(regex.test('world')).toBe(false);
    });

    it('should return non-matching regex for dangerous patterns', () => {
      const regex = createSafeRegex('(a+)+');
      expect(regex.test('aaaaaa')).toBe(false);
      expect(regex.test('')).toBe(false);
    });

    it('should return non-matching regex for invalid patterns', () => {
      const regex = createSafeRegex('[invalid');
      expect(regex.test('anything')).toBe(false);
    });

    it('should support regex flags', () => {
      const regex = createSafeRegex('hello', 'gi');
      expect(regex.test('HELLO')).toBe(true);
    });

    it('should support global flag for exec', () => {
      const regex = createSafeRegex('\\d+', 'g');
      const match = regex.exec('abc 123 def 456');
      expect(match).not.toBeNull();
      expect(match![0]).toBe('123');
    });

    it('should handle typical HIPAA rule patterns', () => {
      // SSN pattern from the database
      const ssnRegex = createSafeRegex('\\b\\d{3}-\\d{2}-\\d{4}\\b');
      expect(ssnRegex.test('123-45-6789')).toBe(true);
      expect(ssnRegex.test('hello world')).toBe(false);
    });
  });
});
