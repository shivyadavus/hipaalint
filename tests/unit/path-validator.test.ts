import { describe, it, expect } from 'vitest';
import {
  validateScanPath,
  validateOutputDirectory,
  isSymlink,
  sanitizeFilename,
  SecurityError,
} from '../../src/security/path-validator.js';
import { resolve } from 'path';

describe('Path Validator', () => {
  describe('validateScanPath', () => {
    it('should resolve a valid path', () => {
      const result = validateScanPath('.');
      expect(result).toBe(resolve('.'));
    });

    it('should reject empty paths', () => {
      expect(() => validateScanPath('')).toThrow(SecurityError);
      expect(() => validateScanPath('   ')).toThrow(SecurityError);
    });

    it('should reject paths with null bytes', () => {
      expect(() => validateScanPath('foo\0bar')).toThrow(SecurityError);
      expect(() => validateScanPath('test\0.ts')).toThrow('Null byte detected');
    });

    it('should reject non-existent paths', () => {
      expect(() => validateScanPath('/definitely/does/not/exist/xyz123')).toThrow(SecurityError);
    });

    it('should return an absolute path', () => {
      const result = validateScanPath('.');
      expect(result).toMatch(/^[A-Z]:\\|^\//); // Windows or Unix absolute path
    });
  });

  describe('validateOutputDirectory', () => {
    it('should resolve a valid output directory', () => {
      const result = validateOutputDirectory('.');
      expect(result).toBe(resolve('.'));
    });

    it('should reject empty paths', () => {
      expect(() => validateOutputDirectory('')).toThrow(SecurityError);
    });

    it('should reject paths with null bytes', () => {
      expect(() => validateOutputDirectory('out\0put')).toThrow('Null byte detected');
    });

    it('should reject system directories on Windows', () => {
      // Only test on Windows
      if (process.platform === 'win32') {
        expect(() => validateOutputDirectory('C:\\Windows')).toThrow(SecurityError);
        expect(() => validateOutputDirectory('C:\\Windows\\System32')).toThrow(SecurityError);
        expect(() => validateOutputDirectory('C:\\Program Files')).toThrow(SecurityError);
      }
    });

    it('should reject system directories on Unix', () => {
      // Only test on Unix
      if (process.platform !== 'win32') {
        expect(() => validateOutputDirectory('/etc')).toThrow(SecurityError);
        expect(() => validateOutputDirectory('/etc/cron.d')).toThrow(SecurityError);
        expect(() => validateOutputDirectory('/sys')).toThrow(SecurityError);
        expect(() => validateOutputDirectory('/proc')).toThrow(SecurityError);
      }
    });
  });

  describe('isSymlink', () => {
    it('should return false for regular files', () => {
      expect(isSymlink('package.json')).toBe(false);
    });

    it('should return false for non-existent paths', () => {
      expect(isSymlink('/nonexistent/path/xyz')).toBe(false);
    });

    it('should return false for directories', () => {
      expect(isSymlink('src')).toBe(false);
    });
  });

  describe('sanitizeFilename', () => {
    it('should strip null bytes', () => {
      expect(sanitizeFilename('report\0.json')).toBe('report_.json');
    });

    it('should strip forward slashes', () => {
      expect(sanitizeFilename('../../etc/report.json')).toBe('.._.._etc_report.json');
    });

    it('should strip backslashes', () => {
      expect(sanitizeFilename('..\\..\\report.json')).toBe('.._.._ eport.json'.replace(' ', 'r'));
      // More precise test:
      const result = sanitizeFilename('path\\file.json');
      expect(result).not.toContain('\\');
    });

    it('should leave clean filenames unchanged', () => {
      expect(sanitizeFilename('hipaalint-report-2025-01-01.json')).toBe(
        'hipaalint-report-2025-01-01.json',
      );
    });
  });
});
