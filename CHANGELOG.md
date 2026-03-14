# Changelog

All notable changes to HipaaLint AI are documented here.

## [1.0.0] - 2026-03-14

### Added

- **PHI Detection** — 18 HIPAA identifier detectors (8 regex + 9 variable patterns)
- **Rule Engine** — 266 rules across HIPAA (43), HITRUST CSF (156), and SOC 2 Health (67) with 5 pattern types (code, negative, config, import, semantic)
- **Score Calculator** — Weighted 0-100 scoring with domain breakdown, severity clamping, and "Strong" band classification
- **Auto-Fix** — `--fix` flag for safe, deterministic remediation of HTTP, TLS, and CORS violations
- **CLI** — 5 commands: `scan`, `score`, `report`, `phi`, `rules`
- **MCP Server** — 5 tools with safety annotations (`readOnlyHint`/`destructiveHint`) for Claude Code, Cursor, and other AI agents
- **Reports** — JSON, SARIF (GitHub Code Scanning), and PDF audit report generators
- **Badge Generator** — shields.io badge URLs and self-hosted SVG badges
- **Plugin** — Claude Code plugin with 6 skills (`scan`, `score`, `report`, `phi`, `rules`, `hipaa-compliance`), 1 agent (`compliance-reviewer`), and MCP integration
- **VS Code Extension** — Inline diagnostics, quick fixes, dashboard sidebar, and status bar score
- **JetBrains Plugin** — IntelliJ/WebStorm inspections, quick fixes, tool window dashboard, and project settings
- **GitHub Action** — CI/CD integration with SARIF upload and score thresholds
- **Pre-Commit Hook** — Blocks commits with critical HIPAA violations
- **Security** — Input validation (Zod), path traversal guards, ReDoS protection, regex caching
- **Legal** — Apache 2.0 license with copyright appendix, NOTICE file with third-party attributions, disclaimers in all output surfaces
- **Testing** — Comprehensive test suite across unit, integration, E2E, and benchmark suites
