import { describe, it, expect } from 'vitest';
import {
  generateBadgeUrl,
  generateBadgeMarkdown,
  generateBadgeSvg,
} from '../../src/reports/badge-generator.js';
import type { ComplianceScore } from '../../src/engine/types.js';

function createMockScore(overallScore: number, band: ComplianceScore['band']): ComplianceScore {
  const emptyDomain = {
    score: 100,
    weight: 0,
    totalCheckpoints: 0,
    passedCheckpoints: 0,
    failedCheckpoints: 0,
    warningCheckpoints: 0,
    findings: [],
  };

  return {
    overallScore,
    band,
    domainScores: {
      phiProtection: emptyDomain,
      encryption: emptyDomain,
      accessControl: emptyDomain,
      auditLogging: emptyDomain,
      infrastructure: emptyDomain,
      aiGovernance: emptyDomain,
    },
    metadata: {
      scannedAt: new Date().toISOString(),
      filesScanned: 10,
      rulesEvaluated: 33,
      framework: 'hipaa',
      sensitivity: 'balanced',
      engineVersion: '1.0.0',
    },
  };
}

describe('Badge Generator', () => {
  describe('generateBadgeUrl', () => {
    it('should return shields.io URL', () => {
      const score = createMockScore(92, 'strong');
      const url = generateBadgeUrl(score);
      expect(url).toContain('https://img.shields.io/badge/');
    });

    it('should include score value in URL', () => {
      const score = createMockScore(85, 'strong');
      const url = generateBadgeUrl(score);
      expect(url).toContain('85');
    });

    it('should use green color for compliant band', () => {
      const score = createMockScore(92, 'strong');
      const url = generateBadgeUrl(score);
      expect(url).toContain('00c853');
    });

    it('should use red color for critical band', () => {
      const score = createMockScore(20, 'critical');
      const url = generateBadgeUrl(score);
      expect(url).toContain('d32f2f');
    });

    it('should use amber color for needs_improvement band', () => {
      const score = createMockScore(65, 'needs_improvement');
      const url = generateBadgeUrl(score);
      expect(url).toContain('ff9800');
    });
  });

  describe('generateBadgeMarkdown', () => {
    it('should return valid markdown image link', () => {
      const score = createMockScore(85, 'strong');
      const md = generateBadgeMarkdown(score, 'https://github.com/test/repo');
      expect(md).toMatch(/^\[!\[HipaaLint Score\]\(.*\)\]\(.*\)$/);
    });

    it('should use provided repo URL', () => {
      const score = createMockScore(85, 'strong');
      const md = generateBadgeMarkdown(score, 'https://github.com/test/repo');
      expect(md).toContain('https://github.com/test/repo');
    });

    it('should use # when no repo URL provided', () => {
      const score = createMockScore(85, 'strong');
      const md = generateBadgeMarkdown(score);
      expect(md).toContain('](#)');
    });
  });

  describe('generateBadgeSvg', () => {
    it('should return valid SVG string', () => {
      const score = createMockScore(85, 'strong');
      const svg = generateBadgeSvg(score);
      expect(svg).toContain('<svg');
      expect(svg).toContain('</svg>');
    });

    it('should include score value in SVG', () => {
      const score = createMockScore(85, 'strong');
      const svg = generateBadgeSvg(score);
      expect(svg).toContain('85/100');
    });

    it('should use band-appropriate color', () => {
      const score = createMockScore(85, 'strong');
      const svg = generateBadgeSvg(score);
      expect(svg).toContain('#00c853');
    });

    it('should include HipaaLint label', () => {
      const score = createMockScore(85, 'strong');
      const svg = generateBadgeSvg(score);
      expect(svg).toContain('HipaaLint');
    });
  });
});
