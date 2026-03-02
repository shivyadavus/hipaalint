# AGENTS.md — HipaaLint AI

## Project Overview

HipaaLint AI is a HIPAA compliance enforcement tool for AI-assisted development. It detects PHI exposure, evaluates compliance rules, calculates weighted scores, and generates audit reports.

## Architecture

Three-layer architecture:
1. **Layer 1 — Plugin/Skills** (`skills/`, `commands/`, `agents/`) — Directives for AI agents
2. **Layer 2 — MCP Server** (`src/mcp-server/`) — 5 tools exposed via Model Context Protocol
3. **Layer 3 — Engine** (`src/engine/`) — PHI detector, rule evaluator, score calculator

## Tech Stack

- **Language**: TypeScript 5.7, Node.js 20+
- **Build**: tsc with Node16 module resolution
- **Database**: SQLite via better-sqlite3
- **Validation**: Zod schemas
- **Testing**: Vitest with v8 coverage
- **CLI**: Commander.js
- **PDF**: pdfkit

## Key Commands

```bash
npm run build        # Compile TypeScript
npm run test         # Run test suite
npm run lint         # ESLint check
npm run typecheck    # TypeScript type-check
npm run dev          # Watch mode
```

## Coding Standards

1. **Strict TypeScript** — No `any` types, enable all strict checks
2. **Zod validation** — All external inputs validated via Zod schemas in `src/engine/types.ts`
3. **No PHI in logs** — Never log PHI, use tokenized identifiers
4. **Sanitize output** — Code snippets in findings are truncated to 200 chars
5. **Close resources** — Always call `.close()` on `RuleEvaluator` in `finally` blocks

## File Naming

- `kebab-case.ts` for all source files
- Tests in `tests/unit/` and `tests/integration/`
- Test fixtures in `tests/fixtures/compliant/` and `tests/fixtures/non-compliant/`

## Core Types (src/engine/types.ts)

- `ComplianceFinding` — A single violation with location, severity, citation, remediation
- `ScanResult` — Aggregate scan output with findings array and metadata
- `ComplianceScore` — Weighted score with domain breakdowns and band classification
- `Rule` — A compliance rule with pattern type and config
- `ComplianceReport` — Full audit report with score, findings, recommendations

## Adding New Rules

1. Add SQL INSERT to `src/rules/db/seed-hipaa.sql`
2. Choose pattern type: `code_pattern`, `negative_pattern`, `config_pattern`, `import_pattern`, or `ast_pattern`
3. Define `pattern_config` JSON with regex patterns, variable names, or import lists
4. Test with fixtures in `tests/fixtures/non-compliant/`

## HIPAA Considerations

- All 18 HIPAA identifiers are detected (45 CFR §164.514(b)(2))
- PHI Protection domain has highest weight (25%)
- Critical PHI findings clamp score to max 69 (cannot be compliant)
- Code snippets are sanitized before inclusion in reports
