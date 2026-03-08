import Database from 'better-sqlite3';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { Rule, Framework, Checkpoint } from '../engine/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface RuleRow {
  id: number;
  frameworkId: number;
  ruleId: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  citation: string;
  remediation: string;
  patternType: string;
  patternConfig: string;
  isRequired: number;
}

function rowToRule(row: RuleRow): Rule {
  return {
    id: row.id,
    frameworkId: row.frameworkId,
    ruleId: row.ruleId,
    title: row.title,
    description: row.description,
    severity: row.severity as Rule['severity'],
    category: row.category as Rule['category'],
    citation: row.citation,
    remediation: row.remediation,
    patternType: row.patternType as Rule['patternType'],
    patternConfig: row.patternConfig,
    isRequired: Boolean(row.isRequired),
  };
}

const RULE_COLUMNS = `id, framework_id as frameworkId, rule_id as ruleId, title, 
  description, severity, category, citation, remediation,
  pattern_type as patternType, pattern_config as patternConfig, 
  is_required as isRequired`;

const RULE_COLUMNS_PREFIXED = `r.id, r.framework_id as frameworkId, r.rule_id as ruleId, r.title, 
  r.description, r.severity, r.category, r.citation, r.remediation,
  r.pattern_type as patternType, r.pattern_config as patternConfig, 
  r.is_required as isRequired`;

export class RuleDatabase {
  private db: Database.Database;

  constructor(dbPath?: string) {
    const resolvedPath = dbPath || join(__dirname, 'db', 'hipaalint.db');
    this.db = new Database(resolvedPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
  }

  initSchema(): void {
    const schemaPath = join(__dirname, 'db', 'schema.sql');
    const schema = readFileSync(schemaPath, 'utf-8');
    this.db.exec(schema);
  }

  seedHIPAA(): void {
    const seedPath = join(__dirname, 'db', 'seed-hipaa.sql');
    const seed = readFileSync(seedPath, 'utf-8');
    this.db.exec(seed);
  }

  seedIaC(): void {
    const seedPath = join(__dirname, 'db', 'seed-iac.sql');
    const seed = readFileSync(seedPath, 'utf-8');
    this.db.exec(seed);
  }

  seedHITRUST(): void {
    const seedPath = join(__dirname, 'db', 'seed-hitrust.sql');
    const seed = readFileSync(seedPath, 'utf-8');
    this.db.exec(seed);
  }

  seedSOC2Health(): void {
    const seedPath = join(__dirname, 'db', 'seed-soc2-health.sql');
    const seed = readFileSync(seedPath, 'utf-8');
    this.db.exec(seed);
  }

  initialize(): void {
    this.initSchema();
    const row = this.db.prepare('SELECT COUNT(*) as count FROM frameworks').get() as {
      count: number;
    };
    if (row.count === 0) {
      this.seedHIPAA();
      this.seedIaC();
      this.seedHITRUST();
      this.seedSOC2Health();
    }
  }

  // ── Framework queries ──

  getFrameworks(): Framework[] {
    return this.db
      .prepare('SELECT id, name, version, description, source_url as sourceUrl FROM frameworks')
      .all() as Framework[];
  }

  getFramework(name: string): Framework | undefined {
    return this.db
      .prepare(
        'SELECT id, name, version, description, source_url as sourceUrl FROM frameworks WHERE name = ?',
      )
      .get(name) as Framework | undefined;
  }

  // ── Rule queries ──

  getRulesByFramework(frameworkName: string): Rule[] {
    return (
      this.db
        .prepare(
          `SELECT ${RULE_COLUMNS_PREFIXED}
         FROM rules r JOIN frameworks f ON r.framework_id = f.id
         WHERE f.name = ? ORDER BY r.severity, r.category`,
        )
        .all(frameworkName) as RuleRow[]
    ).map(rowToRule);
  }

  getRulesBySeverity(severity: string, frameworkName?: string): Rule[] {
    if (frameworkName) {
      return (
        this.db
          .prepare(
            `SELECT ${RULE_COLUMNS_PREFIXED}
           FROM rules r JOIN frameworks f ON r.framework_id = f.id
           WHERE r.severity = ? AND f.name = ?`,
          )
          .all(severity, frameworkName) as RuleRow[]
      ).map(rowToRule);
    }
    return (
      this.db
        .prepare(`SELECT ${RULE_COLUMNS} FROM rules WHERE severity = ?`)
        .all(severity) as RuleRow[]
    ).map(rowToRule);
  }

  getRulesByCategory(category: string, frameworkName?: string): Rule[] {
    if (frameworkName) {
      return (
        this.db
          .prepare(
            `SELECT ${RULE_COLUMNS_PREFIXED}
           FROM rules r JOIN frameworks f ON r.framework_id = f.id
           WHERE r.category = ? AND f.name = ?`,
          )
          .all(category, frameworkName) as RuleRow[]
      ).map(rowToRule);
    }
    return (
      this.db
        .prepare(`SELECT ${RULE_COLUMNS} FROM rules WHERE category = ?`)
        .all(category) as RuleRow[]
    ).map(rowToRule);
  }

  getRule(ruleId: string): Rule | undefined {
    const row = this.db
      .prepare(`SELECT ${RULE_COLUMNS} FROM rules WHERE rule_id = ?`)
      .get(ruleId) as RuleRow | undefined;
    if (!row) return undefined;
    return rowToRule(row);
  }

  searchRules(keyword: string): Rule[] {
    const pattern = `%${keyword}%`;
    return (
      this.db
        .prepare(
          `SELECT ${RULE_COLUMNS} FROM rules 
         WHERE title LIKE ? OR description LIKE ? OR remediation LIKE ?`,
        )
        .all(pattern, pattern, pattern) as RuleRow[]
    ).map(rowToRule);
  }

  getAllRules(): Rule[] {
    return (
      this.db
        .prepare(`SELECT ${RULE_COLUMNS} FROM rules ORDER BY severity, category`)
        .all() as RuleRow[]
    ).map(rowToRule);
  }

  // ── Checkpoint queries ──

  getCheckpoints(ruleId: number): Checkpoint[] {
    return this.db
      .prepare(
        `SELECT id, rule_id as ruleId, checkpoint_type as checkpointType, 
         config_json as configJson FROM checkpoints WHERE rule_id = ?`,
      )
      .all(ruleId) as Checkpoint[];
  }

  // ── Scan history ──

  saveScanResult(
    projectPath: string,
    framework: string,
    score: number,
    band: string,
    filesScanned: number,
    findingsCount: number,
    findingsSummary: object,
  ): void {
    this.db
      .prepare(
        `INSERT INTO scan_history (project_path, framework, score, band, files_scanned, findings_count, findings_json)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        projectPath,
        framework,
        score,
        band,
        filesScanned,
        findingsCount,
        JSON.stringify(findingsSummary),
      );
  }

  getScanHistory(projectPath: string, limit = 10): Array<Record<string, unknown>> {
    return this.db
      .prepare(
        `SELECT id, project_path as projectPath, framework, score, band, 
         files_scanned as filesScanned, findings_count as findingsCount,
         findings_json as findingsJson, scanned_at as scannedAt
         FROM scan_history WHERE project_path = ?
         ORDER BY scanned_at DESC LIMIT ?`,
      )
      .all(projectPath, limit) as Array<Record<string, unknown>>;
  }

  // ── Utility ──

  getRuleCount(): number {
    const result = this.db.prepare('SELECT COUNT(*) as count FROM rules').get() as {
      count: number;
    };
    return result.count;
  }

  close(): void {
    this.db.close();
  }
}
