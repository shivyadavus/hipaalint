-- ComplianceShield AI — Rule Database Schema
-- SQLite schema for compliance rules, frameworks, and scan history

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ─────────────────────────────────────────────────
-- Frameworks table
-- ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS frameworks (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL UNIQUE,
  version     TEXT NOT NULL,
  description TEXT NOT NULL,
  source_url  TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────────────
-- Rules table
-- ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rules (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  framework_id    INTEGER NOT NULL REFERENCES frameworks(id),
  rule_id         TEXT NOT NULL,
  title           TEXT NOT NULL,
  description     TEXT NOT NULL,
  severity        TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')),
  category        TEXT NOT NULL CHECK(category IN ('phi_protection','encryption','access_control','audit_logging','infrastructure','ai_governance')),
  citation        TEXT NOT NULL,
  remediation     TEXT NOT NULL,
  pattern_type    TEXT NOT NULL CHECK(pattern_type IN ('code_pattern','ast_pattern','config_pattern','import_pattern','negative_pattern')),
  pattern_config  TEXT NOT NULL, -- JSON
  is_required     INTEGER NOT NULL DEFAULT 1,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(framework_id, rule_id)
);

-- ─────────────────────────────────────────────────
-- Checkpoints table
-- ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS checkpoints (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id         INTEGER NOT NULL REFERENCES rules(id),
  checkpoint_type TEXT NOT NULL,
  config_json     TEXT NOT NULL, -- JSON
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────────────
-- Scan history table
-- ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_history (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  project_path  TEXT NOT NULL,
  framework     TEXT NOT NULL,
  score         REAL NOT NULL,
  band          TEXT NOT NULL,
  files_scanned INTEGER NOT NULL,
  findings_count INTEGER NOT NULL,
  findings_json TEXT NOT NULL, -- JSON (summary only, no code)
  scanned_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────────────
-- Indexes
-- ─────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_rules_framework ON rules(framework_id);
CREATE INDEX IF NOT EXISTS idx_rules_severity ON rules(severity);
CREATE INDEX IF NOT EXISTS idx_rules_category ON rules(category);
CREATE INDEX IF NOT EXISTS idx_checkpoints_rule ON checkpoints(rule_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_project ON scan_history(project_path);
CREATE INDEX IF NOT EXISTS idx_scan_history_date ON scan_history(scanned_at);
