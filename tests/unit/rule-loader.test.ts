import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { RuleDatabase } from '../../src/rules/rule-loader.js';
import { join } from 'path';
import { mkdirSync, rmSync } from 'fs';
import { tmpdir } from 'os';

const TEST_DB_DIR = join(tmpdir(), 'hipaalint-test');

function createTestDbPath(): string {
  return join(TEST_DB_DIR, `test-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
}

describe('RuleDatabase', () => {
  let db: RuleDatabase;
  let dbPath: string;

  beforeEach(() => {
    mkdirSync(TEST_DB_DIR, { recursive: true });
    dbPath = createTestDbPath();
    db = new RuleDatabase(dbPath);
    db.initialize();
  });

  afterEach(() => {
    db.close();
    try {
      rmSync(dbPath, { force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('initialization', () => {
    it('should initialize schema without error', () => {
      const newPath = createTestDbPath();
      const newDb = new RuleDatabase(newPath);
      expect(() => newDb.initialize()).not.toThrow();
      newDb.close();
      rmSync(newPath, { force: true });
    });

    it('should seed HIPAA rules on first initialization', () => {
      expect(db.getRuleCount()).toBe(33);
    });

    it('should not re-seed if rules already exist', () => {
      db.initialize(); // Call again
      expect(db.getRuleCount()).toBe(33);
    });
  });

  describe('framework queries', () => {
    it('should return frameworks list', () => {
      const frameworks = db.getFrameworks();
      expect(frameworks.length).toBeGreaterThan(0);
      expect(frameworks[0]!.name).toBe('hipaa');
    });

    it('should find framework by name', () => {
      const framework = db.getFramework('hipaa');
      expect(framework).toBeDefined();
      expect(framework!.name).toBe('hipaa');
    });

    it('should return undefined for unknown framework', () => {
      const framework = db.getFramework('nonexistent');
      expect(framework).toBeUndefined();
    });
  });

  describe('rule queries', () => {
    it('should get rules by framework', () => {
      const rules = db.getRulesByFramework('hipaa');
      expect(rules.length).toBe(33);
    });

    it('should get rules by severity', () => {
      const critical = db.getRulesBySeverity('critical');
      expect(critical.length).toBeGreaterThan(0);
      for (const rule of critical) {
        expect(rule.severity).toBe('critical');
      }
    });

    it('should get rules by severity with framework filter', () => {
      const critical = db.getRulesBySeverity('critical', 'hipaa');
      expect(critical.length).toBeGreaterThan(0);
    });

    it('should get rules by category', () => {
      const phiRules = db.getRulesByCategory('phi_protection');
      expect(phiRules.length).toBeGreaterThan(0);
      for (const rule of phiRules) {
        expect(rule.category).toBe('phi_protection');
      }
    });

    it('should get specific rule by ruleId', () => {
      const rule = db.getRule('HIPAA-PHI-001');
      expect(rule).toBeDefined();
      expect(rule!.ruleId).toBe('HIPAA-PHI-001');
      expect(rule!.title).toBe('PHI in Log Statements');
    });

    it('should return undefined for unknown ruleId', () => {
      const rule = db.getRule('NONEXISTENT-001');
      expect(rule).toBeUndefined();
    });

    it('should search rules by keyword', () => {
      const results = db.searchRules('encryption');
      expect(results.length).toBeGreaterThan(0);
    });

    it('should return correct rule count', () => {
      expect(db.getRuleCount()).toBe(33);
    });

    it('should return all rules ordered by severity and category', () => {
      const rules = db.getAllRules();
      expect(rules.length).toBe(33);
    });
  });

  describe('scan history', () => {
    it('should save and retrieve scan history', () => {
      db.saveScanResult('/test/project', 'hipaa', 85, 'strong', 50, 3, { test: true });
      const history = db.getScanHistory('/test/project');
      expect(history.length).toBe(1);
      expect(history[0]!['score']).toBe(85);
      expect(history[0]!['band']).toBe('strong');
    });
  });

  describe('close', () => {
    it('should close without error', () => {
      const newPath = createTestDbPath();
      const newDb = new RuleDatabase(newPath);
      newDb.initialize();
      expect(() => newDb.close()).not.toThrow();
      rmSync(newPath, { force: true });
    });
  });
});
