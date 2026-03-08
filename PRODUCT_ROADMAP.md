# Product Roadmap — HipaaLint AI

Single source of truth for completed work, planned work, tech debt, backlog, and GTM.
Last updated: 2026-03-08.

---

## Table of Contents

1. [Completed Phases](#completed-phases)
2. [Critical Analysis Plan (Phase 6)](#critical-analysis-plan-phase-6)
3. [Backlog](#backlog)
4. [Multi-Platform Expansion (B-25)](#b-25-multi-platform-marketplace-expansion)
5. [Auth & Monetization (B-23)](#b-23-add-authentication-layer--use-anthropic-api-keys-for-pro-features)
6. [GTM Checklist (B-24)](#b-24-gtm-pre-launch-checklist--legal-compliance-sales-marketing-company-setup)
7. [Tech Debt](#tech-debt)
8. [Resolved Items](#resolved-items)

---

# Completed Phases

## Phase 1: Core Engine (COMPLETE)

- [x] Define Zod type system with all enums, schemas, and domain weights
- [x] Implement PHI detector with 8 regex patterns and 9 variable name patterns
- [x] Support all 18 HIPAA identifiers (45 CFR §164.514(b)(2))
- [x] Context-aware detection (log statements, error handlers, API responses, etc.)
- [x] Sensitivity levels: strict, balanced, relaxed
- [x] Finding deduplication

## Phase 2: Rule Database (COMPLETE)

- [x] SQLite schema: frameworks, rules, checkpoints, scan_history tables
- [x] Seed 33 HIPAA rules across 6 compliance domains
- [x] Rule loader with query methods (by framework, severity, category, keyword search)
- [x] DB initialization and seeding scripts
- [x] Pattern types: code_pattern, negative_pattern, import_pattern, config_pattern, semantic_pattern

## Phase 3: Scoring & Evaluation (COMPLETE)

- [x] Rule evaluator with file collection and pattern matching
- [x] 5 pattern evaluation types (code, negative, config, import, semantic)
- [x] Weighted 6-domain scoring algorithm (0-100)
- [x] Score clamping rules (critical PHI → 69, no encryption → 59, no MFA → 79)
- [x] Graduated clamping (1 critical → 69, 2-5 → 59, 6+ → 49)
- [x] Band classification: strong, needs_improvement, at_risk, critical

## Phase 4: Reports & CLI (COMPLETE)

- [x] JSON report generator with date-stamping
- [x] SARIF report generator (GitHub Code Scanning compatible)
- [x] PDF audit report (5-page professional layout)
- [x] Badge generator (shields.io URL, markdown, SVG)
- [x] CLI: scan, score, report, phi, rules commands
- [x] Terminal output with chalk color coding
- [x] Disclaimer in all output formats

## Phase 5A: MCP Server & Plugin (COMPLETE)

- [x] MCP server with 5 tools: compliance_scan, compliance_score, compliance_report, phi_detect, compliance_rules
- [x] Claude Code plugin manifest (.claude-plugin/plugin.json)
- [x] MCP configuration (.mcp.json)
- [x] Compliance reviewer agent (agents/compliance-reviewer.md)
- [x] Slash commands: /compliance:scan, /compliance:report
- [x] HIPAA compliance skill with full reference docs

## Phase 5B: CI/CD & Distribution (COMPLETE)

- [x] GitHub Actions CI workflow (lint, typecheck, format, test, build)
- [x] GitHub Actions release workflow (npm publish, GitHub releases)
- [x] GitHub Action for CI/CD integration (action.yml with inputs/outputs)
- [x] Pre-commit hook for blocking critical violations
- [x] Plugin validation script
- [x] Publish pipeline script
- [x] Cross-platform CI: Ubuntu + macOS + Windows x Node 18/20/22

## Phase 5C: Hardening & Launch Readiness (COMPLETE)

- [x] Input sanitization, path traversal guards, ReDoS protection
- [x] Semantic pattern matching (renamed from ast_pattern)
- [x] Inline suppression comments (disable-line, disable-next-line, block disable/enable)
- [x] Test coverage: 94.89% statements, 86.66% branches, 276 tests
- [x] Integration tests for MCP server tools and CLI commands
- [x] E2E test scanning a real project
- [x] Performance: scan timeout, max depth, file size limits
- [x] Auto-fix with --fix and --dry-run (HTTP, TLS, CORS)
- [x] .hipaalintignore support
- [x] Base64 PHI detection
- [x] Binary file skip tracking with reasons
- [x] Graceful shutdown (SIGINT/SIGTERM)

---

# Critical Analysis Plan (Phase 6)

A critical analysis identified 10 issues that could cause Claude plugin marketplace rejection or make HipaaLint not useful in practice. All 10 issues have been resolved.

## Phase 6A: Marketplace Rejection Blockers (Issues 1, 2, 5, 10) — COMPLETE

### Issue 1 — Rename "Compliant" Band to "Strong"
The word "compliant" implies HIPAA certification. Renamed to "strong" in all enums, outputs, reports, and tests.

### Issue 2 — Graduated Clamping + MFA Clamp
1 critical and 10 criticals no longer produce the same score. Graduated: 1 critical → cap 69, 2-5 → cap 59, 6+ → cap 49. MFA clamp (cap 79) now active via keyword matching.

### Issue 5 — Rename "ast_pattern" to "semantic_pattern"
The method does regex + multi-line lookahead, not AST parsing. Renamed throughout codebase and seed SQL.

### Issue 10 — Strengthen Disclaimer in All Outputs
CLI scan/phi/report commands, JSON/SARIF reports, and MCP tools all include disclaimer text.

## Phase 6B: Safety & Reliability (Issues 3, 4) — COMPLETE

### Issue 3 — Auto-Fixer: Skip Comments
Fixer no longer modifies code inside `//` or `/* */` comments. HTTPS fix description includes verification warning.

### Issue 4 — Scan Timeout + Depth Limit
Added `--timeout` (default 60s) and `--max-depth` (default 50) to prevent hanging on `/` or deeply nested directories.

## Phase 6C: False Positive Reduction (Issues 6, 7) — COMPLETE

### Issue 6 — Reduce PHI Detector False Positives
- IP addresses: private ranges (10.x, 172.16-31.x, 192.168.x) excluded
- Emails: infrastructure prefixes (noreply@, admin@, bot@, etc.) excluded
- Dates: lowered confidence, excluded lines with release/version/copyright keywords
- Variable names: type/interface definitions skipped

### Issue 7 — Inline Suppression Comments
Added `// hipaalint-disable-next-line [rule-id]`, `// hipaalint-disable-line`, and block `// hipaalint-disable` / `// hipaalint-enable` support.

## Phase 6D: Rule Coverage Expansion (Issues 8, 9) — COMPLETE

### Issue 8 — Expand Import Patterns
MFA rule (AC-004) now recognizes Auth0, Cognito, Okta, Firebase Auth, Passport, NextAuth, Clerk, Supabase. Audit logging (AL-001) recognizes Pino, Sentry, Datadog, Morgan.

### Issue 9 — 2025 HIPAA Security Rule Updates
Added 4 new rules: INF-004 (network segmentation), INF-005 (vulnerability scanning), AL-004 (breach notification), INF-006 (data backup). Total: 33 rules.

---

# Backlog

Marketplace readiness findings from honest evaluation (2026-03-07).
Organized by priority: P0 (blocking) → P1 (high) → P2 (medium) → P3 (low).

## P0 — Blocking (must fix before marketplace submission)

### B-01: Fix `marketplace.json` source format
**Effort**: Small (15 min)
**Files**: `.claude-plugin/marketplace.json`

Current `"source": "."` (relative path) only works for Git-based discovery. Change to:
```json
"source": { "type": "github", "repo": "shivyadavus/hipaalint" }
```

### B-02: Fix repository URL mismatch in `package.json`
**Effort**: Small (5 min)
**Files**: `package.json`
**Ref**: TD-6

`repository.url` points to `hipaalint-ai.git` but actual repo is `hipaalint`. Will cause npm publish failure and broken GitHub links.

### B-03: Implement stubbed `config_pattern` evaluation
**Effort**: Large (4-6 hrs)
**Files**: `src/engine/rule-evaluator.ts`
**Ref**: TD-1

`evaluateConfigPattern()` returns empty for most projects. Rules HIPAA-ENC-003 (encryption at rest), HIPAA-AC-003 (session timeout), HIPAA-AL-003 (log retention), HIPAA-AI-002 (AI data governance) are defined but rarely fire. Reviewers will notice 4 rules that don't work.

### B-04: Add MCP server configuration example to README
**Effort**: Small (15 min)
**Files**: `README.md`

Users installing the plugin won't know how to configure the MCP server in Claude Code or Cursor. Need a copy-paste JSON block.

---

### B-23: Add authentication layer — use Anthropic API keys for Pro features
**Effort**: Large (2-3 weeks)
**Files**: `src/engine/`, `src/mcp-server/index.ts`, `src/cli/index.ts`, `package.json`

**Context**: Currently HipaaLint is 100% local — zero network calls, zero auth, zero API keys. The scan engine uses regex + SQLite only. To monetize via open-core (free CLI + paid Pro), developers should authenticate using their existing Claude subscription or Anthropic API keys rather than building separate billing infrastructure.

**Architecture Plan**:

**Phase A — API Key Validation Layer (3-5 days)**
1. Create `src/auth/license-manager.ts`:
   - Accept `HIPAALINT_API_KEY` env var or `--api-key` CLI flag
   - Validate key format (prefix `hl_` + 32-char hex)
   - Local validation first (offline-capable), server-side for Pro features
2. Create `src/auth/entitlements.ts`:
   - Define feature flags: `{ pdfReports, scanHistory, ciThresholds, configFile, badgeApi }`
   - Free tier: all flags false (features gated but engine fully functional)
   - Pro tier: flags unlocked on valid API key

**Phase B — Anthropic API Key Integration (3-5 days)**
3. Add optional Anthropic API key pass-through (`ANTHROPIC_API_KEY` env var):
   - If user has Claude subscription, validate via lightweight API ping
   - Map subscription tier to HipaaLint entitlements (Pro, Team, Enterprise)
   - Fallback: if no Anthropic key, check for `HIPAALINT_API_KEY` instead
4. MCP server integration:
   - Read API key from MCP server env config in `.mcp.json`
   - Pass `env: { "ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}" }` through plugin config
   - Validate on first tool call, cache result for session

**Phase C — Feature Gating (3-5 days)**
5. Gate Pro features at the function level:
   - `hipaalint report --format pdf` → check entitlement, show preview + upgrade prompt if free
   - `hipaalint score --threshold N` → CI enforcement requires Pro
   - Scan history persistence (SQLite `scan_history` table) → Pro only
   - `.hipaalintrc.json` config file loading → Pro only
6. Add `--free` flag to always use free tier (for CI/testing)

**Phase D — Billing Backend (5-7 days)**
7. Set up Paddle (Merchant of Record) for payment processing:
   - Handles global tax (VAT/GST/sales tax) automatically
   - License key generation built-in
   - No need to register for sales tax in 45+ US states
   - ~5% + $0.50 per transaction (cheaper than hiring a tax accountant)
8. Create `/api/validate-license` endpoint (lightweight, hosted on Vercel/Cloudflare):
   - Accepts license key → returns entitlements JSON
   - Cache response locally for 24hrs (offline-capable)
   - Degrade gracefully to free tier on network failure

**Key Design Decisions**:
- Free tier stays 100% offline — no network calls ever
- Pro validation happens once per session, cached locally
- Network failure = free tier (never block the user)
- Anthropic API key validation is a convenience, not a requirement
- License keys work independently for non-Claude users (Cursor, VS Code, etc.)

**Dependencies**: B-13 (config file support), Paddle account setup (GTM item)

---

### B-24: GTM Pre-Launch Checklist — legal, compliance, sales, marketing, company setup
**Effort**: Large (2-4 weeks elapsed, ~40 hrs work)

**Context**: Publishing a HIPAA compliance tool creates liability exposure that a typical developer tool does not. This checklist covers everything needed to publish without creating personal liability for the founders. Items are ordered by priority — blocking items must complete before any revenue.

**BLOCKING — Before Any Revenue**:

| # | Action | Cost | Timeline | Notes |
|---|--------|------|----------|-------|
| 1 | **Form Wyoming LLC** (or Delaware C-Corp if VC planned) | $150-300 | 1-3 days | Wyoming: no state income tax, charging order protection, $50/yr. File at Wyoming SOS online. Use ZenBusiness or Northwest Registered Agent. |
| 2 | **Get EIN from IRS** | Free | Same day | IRS Form SS-4 online, 10 minutes |
| 3 | **Open business bank account** | Free | 1 day | Mercury or Relay (free for SaaS founders) |
| 4 | **Get Tech E&O + Cyber Liability insurance** | $1,200-3,000/yr | 1-3 days | CRITICAL for HIPAA-adjacent tools. Must cover "failure to detect" claims. Get quotes from Embroker (startup bundle), Hiscox, or Coalition. |
| 5 | **Draft Terms of Service** | $100-1,500 | 1-2 weeks | Must include: source code handling clause ("we never store your code"), "as-is" warranty disclaimer, liability cap (fees paid in prior 12 months), HIPAA compliance disclaimer ("does not certify compliance"), indemnification, governing law (Wyoming). Use Bonterms template + 2hr attorney review. |
| 6 | **Draft Privacy Policy** | Included above | 1-2 weeks | Must state: what you collect (telemetry, email), what you do NOT collect (source code), CCPA + GDPR compliance, third-party processors (Paddle, analytics). Use Termly or TermsFeed template. |
| 7 | **Claim `@hipaalint` npm org scope** | Free | 10 min | Claim `@hipaalint/ai`, `@hipaalint/cli`, `@hipaalint/mcp` to prevent namespace squatting |

**REQUIRED — Before Public Launch**:

| # | Action | Cost | Timeline | Notes |
|---|--------|------|----------|-------|
| 8 | **Set up Paddle account** (Merchant of Record) | Free (5% + $0.50/tx) | 1 day | Handles all global tax automatically. License key generation built-in. |
| 9 | **Add HIPAA disclaimers to all marketing** | Free | 1 day | Use: "helps identify potential HIPAA compliance issues" — NEVER: "ensures compliance" or "HIPAA certified". FTC has fined GoodRx, BetterHelp, Monument for false HIPAA claims. |
| 10 | **Submit to Claude plugin directory** | Free | 1-4 weeks | Two paths: (A) Self-hosted marketplace on GitHub (instant, no approval), (B) Official directory via `clau.de/plugin-directory-submission` for "Anthropic Verified" badge. Launch with Path A, apply for Path B. |
| 11 | **Publish `@hipaalint/ai` to npm** | Free | 1 hour | `npm publish --access public`. Enable 2FA on npm account first. |
| 12 | **Audit dependency licenses** | Free | 1 hour | Run `npx license-checker --production`. Apache 2.0 is incompatible with GPL v2 — verify no GPL v2 deps in the tree. |
| 13 | **Add CLA for contributors** | Free | 2 hours | Use CLA Assistant (free GitHub integration). Required to retain ability to relicense Pro components later. |

**IMPORTANT — Within 30 Days of Launch**:

| # | Action | Cost | Timeline | Notes |
|---|--------|------|----------|-------|
| 14 | **File USPTO trademark for "HipaaLint"** | $250-1,800 | 8-12 months | File intent-to-use (Section 1(b)) for priority date. "HIPAA" is public domain (federal statute), but "HipaaLint" as composite may register on Supplemental Register. Consider stylized logo mark for easier registration. |
| 15 | **Create pricing page + marketing site** | $0-500 | 1 week | Can use GitHub Pages or simple landing page. Must include: pricing tiers, feature comparison, HIPAA disclaimer, TOS link, privacy policy link. |
| 16 | **Set up basic analytics** | Free | 2 hours | PostHog (free tier) or Plausible ($9/mo). Track: installs, scans, Pro conversions, churn. NEVER track source code content. |

**Competitive Disclaimer Language (use this pattern)**:
- Semgrep: liability capped at $500, all warranties disclaimed
- Snyk: liability limited to fees paid in prior 12 months
- Vanta: "no liability for customer's compliance programs"

**Open Source Licensing Strategy**:

| Layer | License | Rationale |
|-------|---------|-----------|
| Core engine (PHI detector, rule evaluator, scorer) | Apache 2.0 | Drives adoption, enterprise-friendly |
| HIPAA rule database (SQL seeds) | Apache 2.0 | Community contribution magnet |
| CLI tool + MCP server | Apache 2.0 | Maximize AI agent ecosystem adoption |
| Pro features (PDF reports, CI enforcement, dashboards) | Proprietary | Revenue-generating, not open |

**Total blocking costs before first dollar of revenue: ~$1,500-$3,500** (LLC + insurance + legal templates).

---

### B-25: Multi-Platform Marketplace Expansion
**Effort**: Large (4-6 weeks across all platforms)

**Context**: HipaaLint currently ships as a Claude Code plugin. To maximize adoption, expand to every major AI coding tool marketplace. The MCP server is the universal adapter — most platforms now support MCP natively. Platform-specific adapters are needed only where MCP isn't supported.

**Rollout Order** (prioritized by developer reach and integration effort):

**Wave 1 — MCP-native platforms (Week 1-2, low effort)**
These platforms support MCP servers natively. HipaaLint's existing MCP server works with zero code changes — only config/documentation needed.

| Platform | Integration | Effort | Notes |
|----------|------------|--------|-------|
| **Cursor** | Native MCP support via `.cursor/mcp.json` | 2 hrs | Add Cursor config example to README. Same `node dist/mcp-server/index.js` command. Cursor is the #2 AI coding tool after VS Code Copilot. |
| **Windsurf (Codeium)** | Native MCP support | 2 hrs | Add config example. Same MCP server. |
| **Zed** | MCP support via extensions | 4 hrs | Add Zed extension config. May need manifest file. |
| **Continue.dev** | Native MCP support | 2 hrs | Open-source AI coding assistant. Add config example. |

**Wave 2 — VS Code Extension (Week 2-4, medium effort)**
VS Code has the largest developer install base. A proper extension unlocks Copilot users, non-AI users, and enterprise teams.

| Component | Work Required | Effort |
|-----------|--------------|--------|
| Extension manifest (`package.json`) | Define contributes: commands, views, diagnostics | 4 hrs |
| Diagnostic provider | Map HipaaLint findings to VS Code `DiagnosticCollection` (squiggly lines) | 8 hrs |
| Commands | Register `hipaalint.scan`, `hipaalint.score`, `hipaalint.fix` commands | 4 hrs |
| Status bar | Show compliance score in VS Code status bar | 2 hrs |
| Settings UI | Expose sensitivity, ignore patterns, threshold in VS Code settings | 2 hrs |
| Publish to VS Code Marketplace | Create publisher account, `vsce package && vsce publish` | 2 hrs |
| **Total** | | **~22 hrs** |

**Wave 3 — JetBrains Plugin (Week 4-5, medium effort)**
IntelliJ, WebStorm, PyCharm — large enterprise presence.

| Component | Work Required | Effort |
|-----------|--------------|--------|
| Plugin descriptor (`plugin.xml`) | Define actions, extensions, dependencies | 4 hrs |
| External annotator | Map findings to JetBrains inspection system | 8 hrs |
| Tool window | Score dashboard panel | 4 hrs |
| Publish to JetBrains Marketplace | Create vendor account, submit for review | 4 hrs |
| **Total** | | **~20 hrs** |

**Wave 4 — OpenAI & Google ecosystems (Week 5-6, exploratory)**

| Platform | Status | Path Forward |
|----------|--------|--------------|
| **GitHub Copilot Extensions** | Copilot Extensions program (preview). Copilot agents can call external tools via function calling. | Build a Copilot Extension that wraps HipaaLint CLI. Requires GitHub App registration. Medium effort (~16 hrs). |
| **OpenAI GPT Store / ChatGPT Plugins** | GPT Actions support external API calls. No MCP support. | Build a lightweight REST API wrapper around HipaaLint engine. Upload OpenAPI spec as GPT Action. Users paste code for scanning. Limited (no file system access). Low priority. |
| **Google Gemini** | Gemini Code Assist supports MCP (announced 2025). Enterprise-focused. | Test MCP server compatibility with Gemini Code Assist. Add config documentation. Low effort if MCP works. |
| **Amazon Q Developer** | Supports custom plugins via Lambda. | Wrap HipaaLint in an AWS Lambda function. Medium effort (~12 hrs). Enterprise-only audience. |

**Technical Strategy**:
- **Core principle**: The MCP server is the universal adapter. Don't fork the engine per-platform.
- **Monorepo structure**: Add `packages/vscode-extension/`, `packages/jetbrains-plugin/` alongside existing `src/`.
- **Shared engine**: All platform adapters import from `@hipaalint/ai` npm package.
- **Platform-specific output**: VS Code → diagnostics, JetBrains → inspections, CLI → terminal, MCP → JSON.

**Dependencies**: B-01 (marketplace.json fix), B-23 (auth layer — license keys must work across all platforms)

---

## P1 — High (strongly recommended before submission)

### B-05: Create `commands/` directory with slash commands
**Effort**: Medium (1-2 hrs)
**Files**: `commands/` (new directory)

Users expect `/scan`, `/score`, `/report`, `/phi`, `/rules` as Claude Code slash commands. Currently only skills and MCP tools work. Either create command definitions or remove from plugin manifest.

### B-06: Add usage examples to `plugin.json`
**Effort**: Small (15 min)
**Files**: `.claude-plugin/plugin.json`

Marketplace listing won't show users how to invoke the tool. Add `examples` field with sample usage for each skill.

### B-07: Add rate limiting on MCP server tools
**Effort**: Medium (1-2 hrs)
**Files**: `src/mcp-server/index.ts`

No throttling on MCP tool calls. A rogue client could hammer the scan tool with unlimited concurrent requests, causing resource exhaustion. Add per-tool rate limits or a global request queue.

### B-08: Use atomic file writes in auto-fixer
**Effort**: Small (30 min)
**Files**: `src/engine/auto-fixer.ts`

Auto-fixer writes files directly via `writeFileSync`. A crash or SIGKILL mid-write corrupts the source file. Use write-to-temp + rename pattern for atomic operations.

### B-09: Add missing HIPAA rule domains
**Effort**: Large (4-6 hrs)
**Files**: `src/rules/db/seed-hipaa.sql`

Missing critical HIPAA requirements:
- Business Associate Agreement (BAA) verification
- Data retention and deletion policies (§164.404)
- Vendor/subcontractor vetting
- Breach notification timeline compliance

### B-10: Document inline suppression comments in README
**Effort**: Small (15 min)
**Files**: `README.md`

The suppression feature exists (`// hipaalint-disable-line`, `// hipaalint-disable-next-line`, block disable/enable) but isn't documented anywhere. Users won't discover it.

---

## P2 — Medium (improve quality, not blocking)

### B-11: Fix naive context detection in PHI detector
**Effort**: Medium (1-2 hrs)
**Files**: `src/engine/phi-detector.ts`

`detectContext()` uses `/\b(console|logger|log|logging|print)\b/` which false-positives on words like `catalog`, `dialogFlow`, `logistic`. Needs word-boundary + syntax-aware matching.

### B-12: Use web-tree-sitter for precise semantic analysis
**Effort**: Large (8+ hrs)
**Files**: `src/engine/rule-evaluator.ts`
**Ref**: TD-2

`web-tree-sitter` is installed but unused. Regex-based semantic rules are approximate. True AST parsing would eliminate false positives in auth middleware detection, log statement analysis, and API response checking.

### B-13: Add `.hipaalintrc.json` configuration file support
**Effort**: Medium (2-3 hrs)
**Files**: `src/engine/rule-evaluator.ts`, `src/cli/index.ts`

Users can't configure sensitivity, ignore patterns, or score thresholds via a project config file. Must use CLI flags every time. A `.hipaalintrc.json` or `hipaalint.config.js` would improve DX.

### B-14: Document publish workflow in CONTRIBUTING.md
**Effort**: Small (15 min)
**Files**: `CONTRIBUTING.md`

`plugin:validate` and `plugin:publish` scripts exist but their purpose/behavior is undocumented. Contributors won't know the checklist before publishing.

### B-15: Add performance regression checks in CI
**Effort**: Medium (1-2 hrs)
**Files**: `.github/workflows/ci.yml`, `tests/benchmark/`

Benchmark tests exist but no baseline metrics or regression detection. A slow rule could silently degrade scan performance. Store benchmark results and fail CI if regression exceeds threshold.

### B-16: Make 1MB file size limit configurable
**Effort**: Small (30 min)
**Files**: `src/engine/rule-evaluator.ts`, `src/engine/types.ts`

The 1MB file skip limit is hardcoded. Large minified files or generated code may exceed this. Add `--max-file-size` CLI option and config field.

---

## P3 — Low (nice to have)

### B-17: Update pre-commit hook branding
**Effort**: Small (5 min)
**Files**: `hooks/pre-commit`
**Ref**: TD-5

References "ComplianceShield" (former project name) instead of "HipaaLint".

### B-18: Add local docs to .gitignore
**Effort**: Small (5 min)
**Files**: `.gitignore`
**Ref**: TD-8

`docs/ProductRoadmap.md`, `docs/TechDebt.md`, and `CLAUDE.md` are local-only but not gitignored.

### B-19: Expand base64 PHI detection coverage
**Effort**: Small (1 hr)
**Files**: `src/engine/phi-detector.ts`

Base64 detection only checks 4 PHI types (SSN, email, MRN, phone). Add name, address, and date-of-birth patterns for encoded content.

### B-20: Add DB init/seed scripts to post-install
**Effort**: Small (30 min)
**Files**: `package.json`, `src/rules/`

First install requires manual `npm run db:init && npm run db:seed`. Add a `postinstall` script or lazy-initialize on first use.

### B-21: Improve phone number regex precision
**Effort**: Small (30 min)
**Files**: `src/engine/phi-detector.ts`

Phone pattern `\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}` matches arbitrary digit sequences like `5551234567` that may be legitimate non-phone numbers. Add context requirements (proximity to "phone", "tel", "call" keywords).

### B-22: Remove unused `web-tree-sitter` dependency (if B-12 deferred)
**Effort**: Small (5 min)
**Files**: `package.json`

If AST parsing (B-12) is deferred long-term, remove `web-tree-sitter` to reduce install size and eliminate a native-addon dependency.

---

# Tech Debt

## TD-1: Config Pattern Evaluation is Stubbed
**Status**: Open | **Severity**: High (blocks marketplace — same as B-03)
**Files**: `src/engine/rule-evaluator.ts`

`evaluateConfigPattern()` returns empty for most projects. Rules HIPAA-ENC-003, HIPAA-AC-003, HIPAA-AL-003, HIPAA-AI-002 are defined but rarely fire.

## TD-2: Semantic Patterns Use Regex, Not AST
**Status**: Open | **Severity**: Medium (same as B-12)
**Files**: `src/engine/rule-evaluator.ts`, `src/engine/phi-detector.ts`

`web-tree-sitter` is installed but unused. Full AST analysis would enable more precise detection.

## TD-4: Deprecated npm Dependencies
**Status**: Partially Resolved | **Severity**: Low
**Files**: `package.json`

`express-rate-limit` CVE patched. 6 moderate vulnerabilities remain in dev dependencies (esbuild/vite/vitest chain) — excluded via `--omit=dev` in CI.

## TD-5: Pre-commit Hook References "ComplianceShield"
**Status**: Open | **Severity**: Low (same as B-17)
**Files**: `hooks/pre-commit`

## TD-6: Repository URL Mismatch
**Status**: Open | **Severity**: Medium (same as B-02)
**Files**: `package.json`

`package.json` has `repository.url` pointing to wrong repo name.

## TD-8: No .gitignore Entry for Local Docs
**Status**: Open | **Severity**: Low (same as B-18)
**Files**: `.gitignore`

---

# Resolved Items

| ID | Description | Resolved In |
|----|-------------|-------------|
| ~~Critical-1~~ | Package exports pointed to MCP server instead of barrel | Phase 6 `c8bb1bb` |
| ~~Critical-2~~ | Windows path separators broke CLI output | Phase 6 `c8bb1bb` |
| ~~Critical-3~~ | CRLF line endings not stripped in rule evaluator | Phase 6 `c8bb1bb` |
| ~~Critical-4~~ | No cross-platform CI (Linux only) | Phase 6 `c8bb1bb` |
| ~~Critical-5~~ | MCP input size limit (already Zod-guarded) | Phase 6 `c8bb1bb` |
| ~~High-1~~ | No graceful shutdown on Ctrl+C | Phase 6 `c8bb1bb` |
| ~~High-2~~ | Score clamping used hardcoded rule IDs | Phase 6 `c8bb1bb` |
| ~~High-3~~ | Empty project returned misleading 100/100 | Phase 6 `c8bb1bb` |
| ~~High-4~~ | No --exclude or .hipaalintignore support | Phase 6 `c8bb1bb` |
| ~~High-5~~ | PDF report and finding-counter untested | Phase 6 `c8bb1bb` |
| ~~Medium-1~~ | No base64 PHI detection | Phase 6 `60b9e65` |
| ~~Medium-2~~ | Binary files silently skipped | Phase 6 `60b9e65` |
| ~~Medium-3~~ | npm audit swallowed failures with `|| true` | Phase 6 `c8bb1bb` |
| ~~Medium-4~~ | express-rate-limit high-severity CVE | Phase 6 `63d73cd` |
| ~~TD-3~~ | Low test coverage (now 94.89%) | Phase 6 |
| ~~TD-7~~ | Missing CLI input validation | Phase 5C |
