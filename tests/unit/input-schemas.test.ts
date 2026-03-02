import { describe, it, expect } from 'vitest';
import {
  ScanOptionsSchema,
  ScoreOptionsSchema,
  ReportOptionsSchema,
  PHIOptionsSchema,
  RulesOptionsSchema,
  MCPScanArgsSchema,
  MCPScoreArgsSchema,
  MCPReportArgsSchema,
  MCPPHIDetectArgsSchema,
  MCPRulesArgsSchema,
} from '../../src/security/input-schemas.js';

describe('CLI Option Schemas', () => {
  describe('ScanOptionsSchema', () => {
    it('should accept valid options with defaults', () => {
      const result = ScanOptionsSchema.parse({});
      expect(result.framework).toBe('hipaa');
      expect(result.sensitivity).toBe('balanced');
      expect(result.maxFiles).toBe(10000);
    });

    it('should accept explicit valid options', () => {
      const result = ScanOptionsSchema.parse({
        framework: 'hipaa',
        sensitivity: 'strict',
        maxFiles: '500',
        json: true,
      });
      expect(result.sensitivity).toBe('strict');
      expect(result.maxFiles).toBe(500);
      expect(result.json).toBe(true);
    });

    it('should reject invalid sensitivity level', () => {
      expect(() => ScanOptionsSchema.parse({ sensitivity: 'ultra' })).toThrow();
    });

    it('should reject non-numeric maxFiles', () => {
      expect(() => ScanOptionsSchema.parse({ maxFiles: 'abc' })).toThrow();
    });

    it('should reject maxFiles exceeding 100000', () => {
      expect(() => ScanOptionsSchema.parse({ maxFiles: '200000' })).toThrow();
    });

    it('should reject maxFiles of 0', () => {
      expect(() => ScanOptionsSchema.parse({ maxFiles: '0' })).toThrow();
    });
  });

  describe('ScoreOptionsSchema', () => {
    it('should accept valid options with defaults', () => {
      const result = ScoreOptionsSchema.parse({});
      expect(result.threshold).toBe(0);
    });

    it('should reject threshold over 100', () => {
      expect(() => ScoreOptionsSchema.parse({ threshold: '150' })).toThrow();
    });
  });

  describe('ReportOptionsSchema', () => {
    it('should accept valid format options', () => {
      const result = ReportOptionsSchema.parse({ format: 'pdf' });
      expect(result.format).toBe('pdf');
    });

    it('should reject invalid format', () => {
      expect(() => ReportOptionsSchema.parse({ format: 'html' })).toThrow();
    });

    it('should accept optional output', () => {
      const result = ReportOptionsSchema.parse({ output: './reports' });
      expect(result.output).toBe('./reports');
    });
  });

  describe('PHIOptionsSchema', () => {
    it('should accept valid sensitivity', () => {
      const result = PHIOptionsSchema.parse({ sensitivity: 'relaxed' });
      expect(result.sensitivity).toBe('relaxed');
    });

    it('should default sensitivity to balanced', () => {
      const result = PHIOptionsSchema.parse({});
      expect(result.sensitivity).toBe('balanced');
    });
  });

  describe('RulesOptionsSchema', () => {
    it('should accept valid category', () => {
      const result = RulesOptionsSchema.parse({ category: 'encryption' });
      expect(result.category).toBe('encryption');
    });

    it('should reject invalid category', () => {
      expect(() => RulesOptionsSchema.parse({ category: 'invalid_cat' })).toThrow();
    });

    it('should reject query over 500 chars', () => {
      expect(() => RulesOptionsSchema.parse({ query: 'x'.repeat(501) })).toThrow();
    });

    it('should accept valid severity', () => {
      const result = RulesOptionsSchema.parse({ severity: 'critical' });
      expect(result.severity).toBe('critical');
    });
  });
});

describe('MCP Argument Schemas', () => {
  describe('MCPScanArgsSchema', () => {
    it('should require path', () => {
      expect(() => MCPScanArgsSchema.parse({})).toThrow();
    });

    it('should reject empty path', () => {
      expect(() => MCPScanArgsSchema.parse({ path: '' })).toThrow();
    });

    it('should accept valid args', () => {
      const result = MCPScanArgsSchema.parse({ path: '/project' });
      expect(result.path).toBe('/project');
      expect(result.framework).toBe('hipaa');
      expect(result.sensitivity).toBe('balanced');
    });
  });

  describe('MCPScoreArgsSchema', () => {
    it('should require path', () => {
      expect(() => MCPScoreArgsSchema.parse({})).toThrow();
    });

    it('should accept valid args with defaults', () => {
      const result = MCPScoreArgsSchema.parse({ path: '/project' });
      expect(result.framework).toBe('hipaa');
    });
  });

  describe('MCPReportArgsSchema', () => {
    it('should accept valid args', () => {
      const result = MCPReportArgsSchema.parse({ path: '/project', format: 'pdf' });
      expect(result.format).toBe('pdf');
    });

    it('should reject invalid format', () => {
      expect(() => MCPReportArgsSchema.parse({ path: '/p', format: 'docx' })).toThrow();
    });
  });

  describe('MCPPHIDetectArgsSchema', () => {
    it('should require code', () => {
      expect(() => MCPPHIDetectArgsSchema.parse({})).toThrow();
    });

    it('should reject empty code', () => {
      expect(() => MCPPHIDetectArgsSchema.parse({ code: '' })).toThrow();
    });

    it('should reject code exceeding 500KB', () => {
      const largeCode = 'x'.repeat(512_001);
      expect(() => MCPPHIDetectArgsSchema.parse({ code: largeCode })).toThrow();
    });

    it('should accept valid code with defaults', () => {
      const result = MCPPHIDetectArgsSchema.parse({ code: 'const x = 1;' });
      expect(result.filePath).toBe('unknown.ts');
      expect(result.sensitivity).toBe('balanced');
    });
  });

  describe('MCPRulesArgsSchema', () => {
    it('should default action to list', () => {
      const result = MCPRulesArgsSchema.parse({});
      expect(result.action).toBe('list');
    });

    it('should accept search action with query', () => {
      const result = MCPRulesArgsSchema.parse({ action: 'search', query: 'phi' });
      expect(result.action).toBe('search');
      expect(result.query).toBe('phi');
    });

    it('should reject invalid action', () => {
      expect(() => MCPRulesArgsSchema.parse({ action: 'delete' })).toThrow();
    });

    it('should reject query over 500 chars', () => {
      expect(() =>
        MCPRulesArgsSchema.parse({ action: 'search', query: 'x'.repeat(501) }),
      ).toThrow();
    });
  });
});
