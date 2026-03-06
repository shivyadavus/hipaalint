# Changelog

All notable changes to HipaaLint AI are documented here.

## [1.0.0] - 2026-03-05

### Added
- **PHI Detection** — 18 HIPAA identifier detectors (8 regex + 9 variable patterns)
- **Rule Evaluator** — 33 rules across 6 compliance domains with 5 pattern types (code, negative, config, import, semantic)
- **Score Calculator** — Weighted 0-100 scoring with domain breakdown and severity clamping
- **Auto-Fix** — `--fix` flag for safe, deterministic remediation of HTTP, TLS, and CORS violations
- **CLI** — 5 commands: `scan`, `score`, `report`, `phi`, `rules`
- **MCP Server** — 5 tools for Claude Code, Cursor, and other AI agents
- **Reports** — JSON, SARIF (GitHub Code Scanning), and PDF audit report generators
- **Badge Generator** — shields.io badge URLs and self-hosted SVG badges
- **Plugin** — Claude Code plugin with 3 skills, 1 agent, and MCP integration
- **Security** — Input validation (Zod), path traversal guards, ReDoS protection, regex caching
- **Testing** — 233 tests across unit, integration, E2E, and benchmark suites
