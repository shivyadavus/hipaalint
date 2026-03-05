<div align="center">

<img src="assets/logo.svg" alt="hipaalint" height="56">

<br><br>

**Catch HIPAA violations before they ship.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)

*PHI detection, compliance scoring, auto-remediation, and audit reports — from your terminal, AI coding agent, or CI/CD pipeline.*

</div>

---

## Why HipaaLint?

A single exposed SSN in a log statement or an `http://` instead of `https://` can trigger a HIPAA violation carrying fines up to **$1.9M per incident**. With AI coding assistants generating code faster than ever, compliance gaps slip through at scale.

HipaaLint scans your codebase against **29 rules across 6 compliance domains**, scores your project 0-100, and **auto-fixes simple violations** — all in under a second.

## Quick Start

```bash
# Install
npm install -g @hipaalint/ai

# Scan your project
hipaalint scan .

# Get your compliance score
hipaalint score .

# Auto-fix simple violations
hipaalint scan . --fix --dry-run    # preview first
hipaalint scan . --fix              # apply fixes

# Generate a PDF audit report
hipaalint report . --format pdf
```

---

## See It In Action

### 1. Scan — Find violations instantly

```bash
hipaalint scan ./src
```

```
🛡️  HipaaLint AI — Scanning...

   Path: ./src
   Framework: hipaa
   Sensitivity: balanced

📊 Results:
   Files scanned: 128
   Rules evaluated: 29
   Duration: 869ms

   🔴 Critical: 31
   🟠 High:     1502
   🟡 Medium:   199
   🔵 Low:      0

🔴 HIPAA-ENC-001: Unencrypted HTTP Usage
   📍 src/api/client.ts:15
   📋 45 CFR §164.312(e)(1) — Transmission Security
   💡 Use https:// for all data transmission. Configure TLS 1.2+ minimum.

🔴 HIPAA-ENC-004: Hardcoded Encryption Key
   📍 src/config/secrets.ts:40
   📋 45 CFR §164.312(a)(2)(iv) — Encryption and Decryption
   💡 Use environment variables or a secrets manager.
```

Every finding includes the **HIPAA citation**, **file location**, and **actionable remediation**.

### 2. Score — Quantify your compliance posture

```bash
hipaalint score ./src
```

```
🛡️  HipaaLint Score

   🔴 Overall: 3.7/100 (critical)

   Domain Breakdown:
   🟠 phi Protection:  0/100   (25% weight)
   🟠 encryption:      0/100   (20% weight)
   🟠 access Control:  0/100   (20% weight)
   🟠 audit Logging:   0/100   (15% weight)
   🟠 infrastructure:  0/100   (10% weight)
   🟠 ai Governance:   37/100  (10% weight)
```

| Band | Score | Meaning |
|------|-------|---------|
| Compliant | 90-100 | Meets baseline HIPAA technical safeguards |
| Needs Improvement | 70-89 | Minor gaps to address |
| At Risk | 40-69 | Significant compliance gaps |
| Critical | 0-39 | Immediate remediation required |

Critical violations automatically clamp the score — exposed PHI caps you at 69, no encryption caps at 59.

### 3. Fix — Auto-remediate simple violations

```bash
hipaalint scan ./src --fix --dry-run
```

```
🔧 Dry Run — 6 fix(es) would be applied:

   ✅ HIPAA-ENC-001 — src/api/tests/conftest.py:16
      Upgraded http:// to https://
      - return AsyncClient(transport=transport, base_url="http://test")
      + return AsyncClient(transport=transport, base_url="https://test")

   ✅ HIPAA-ENC-001 — src/api/tests/test_auth.py:15
      Upgraded http:// to https://
      - return AsyncClient(transport=transport, base_url="http://test")
      + return AsyncClient(transport=transport, base_url="https://test")

   ℹ️  1,726 finding(s) require manual remediation (no auto-fix)
```

| Rule | What it fixes | Transform |
|------|--------------|-----------|
| HIPAA-ENC-001 | Unencrypted HTTP | `http://` → `https://` (preserves localhost) |
| HIPAA-ENC-005 | Weak TLS/SSL | `TLSv1_0` / `SSLv3` → `TLSv1_2` |
| HIPAA-INF-001 | CORS wildcard | `origin: "*"` → `process.env.CORS_ORIGIN` |

The `--dry-run` flag previews every change with a diff before touching any file.

---

## Features

| Feature | Description |
|---------|-------------|
| **PHI Detection** | Detects all 18 HIPAA identifiers (SSN, DOB, MRN, email, phone, etc.) |
| **HipaaLint Score** | Weighted 0-100 score across 6 compliance domains |
| **Auto-Fix** | Safe, deterministic fixes for HTTP, TLS, and CORS violations |
| **29 HIPAA Rules** | Pre-seeded rule database with regex, AST, config, and import patterns |
| **Audit Reports** | JSON, SARIF (GitHub Code Scanning), and PDF reports |
| **MCP Server** | 5 tools for Claude Code, Cursor, and other AI agents |
| **GitHub Action** | CI/CD integration with SARIF upload and score thresholds |
| **Pre-Commit Hook** | Block commits with critical HIPAA violations |
| **Score Badge** | shields.io badge for your README |

## The 6 Compliance Domains

| Domain | Weight | What It Checks |
|--------|--------|----------------|
| **PHI Protection** | 25% | PHI in source code, logs, error handlers, API responses |
| **Encryption** | 20% | TLS/HTTPS enforcement, strong hashing, no hardcoded keys |
| **Access Control** | 20% | Auth middleware, RBAC, session timeout, MFA |
| **Audit Logging** | 15% | Structured audit trails, log retention, PHI scrubbing |
| **Infrastructure** | 10% | CORS security, security headers, rate limiting |
| **AI Governance** | 10% | PHI scrubbing for AI prompts, model input sanitization |

---

## CLI Commands

### `hipaalint scan [path]`
Scan a project for HIPAA violations:
```bash
hipaalint scan ./src --sensitivity strict
hipaalint scan ./src --fix              # auto-fix simple violations
hipaalint scan ./src --fix --dry-run    # preview fixes without writing
hipaalint scan ./src --json             # machine-readable output
hipaalint scan ./src --sarif            # GitHub Code Scanning format
```

### `hipaalint score [path]`
Calculate the HipaaLint Score:
```bash
hipaalint score .                    # display score
hipaalint score . --threshold 80     # fail CI if below 80
hipaalint score . --json             # machine-readable output
```

### `hipaalint report [path]`
Generate audit reports:
```bash
hipaalint report . --format pdf --output ./reports
hipaalint report . --format sarif    # for GitHub Code Scanning
hipaalint report . --format json     # structured JSON report
```

### `hipaalint phi <file>`
Detect PHI in a specific file:
```bash
hipaalint phi ./src/api/patients.ts
```

### `hipaalint rules`
Browse the rule database:
```bash
hipaalint rules --category phi_protection --severity critical
hipaalint rules --query "encryption" --json
```

---

## AI Agent Integration (MCP)

HipaaLint runs as an MCP server, giving AI coding agents 5 compliance tools:

```json
{
  "mcpServers": {
    "hipaalint-ai": {
      "command": "node",
      "args": ["node_modules/@hipaalint/ai/dist/mcp-server/index.js"]
    }
  }
}
```

**Available Tools:**
- `compliance_scan` — Scan project for violations
- `compliance_score` — Calculate compliance score
- `compliance_report` — Generate audit reports (JSON/PDF)
- `phi_detect` — Detect PHI in code snippets
- `compliance_rules` — Search and browse the rule database

**Slash Commands:**
- `/compliance:scan` — Run a compliance scan
- `/compliance:report` — Generate an audit report

## GitHub Action

```yaml
# .github/workflows/compliance.yml
name: Compliance Check
on: [push, pull_request]

jobs:
  hipaa:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: shivyadavus/hipaalint@v1
        with:
          threshold: 70
          sensitivity: balanced
          upload-sarif: true
```

## Pre-Commit Hook

```bash
cp node_modules/@hipaalint/ai/hooks/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit
```

Blocks commits with critical HIPAA violations. Warns on high-severity findings.

## Score Badge

Add to your README:
```markdown
[![HipaaLint Score](https://img.shields.io/badge/HipaaLint-92%2F100-00c853?style=for-the-badge)](https://github.com/your-org/your-repo)
```

---

## Architecture

```
src/
├── engine/                # Core analysis engine
│   ├── types.ts           # Zod-validated type system
│   ├── phi-detector.ts    # 18 HIPAA identifier detectors
│   ├── rule-evaluator.ts  # Pattern matching (5 pattern types)
│   ├── score-calculator.ts # Weighted scoring algorithm
│   ├── auto-fixer.ts      # Auto-remediation engine
│   └── regex-cache.ts     # Compiled regex cache for performance
├── rules/                 # Rule database
│   └── db/                # SQLite schema + 29 HIPAA rules
├── mcp-server/            # MCP server (5 tools)
├── cli/                   # CLI entry point (commander.js)
├── reports/               # JSON, SARIF, PDF generators
└── security/              # Input validation, path safety, ReDoS guards
```

## Supported PHI Types (18 HIPAA Identifiers)

Names, SSN, DOB, Addresses, Phone Numbers, Email, Medical Record Numbers, Health Plan IDs, Account Numbers, Certificate/License Numbers, Vehicle Identifiers, Device IDs, Web URLs, IP Addresses, Biometric IDs, Photos, Geographic Data (ZIP codes), and Dates.

All mapped to specific provisions under **45 CFR §164.514(b)(2)**.

## Contributing

Contributions are welcome! Please read our [AGENTS.md](./AGENTS.md) for coding guidelines that apply to both human and AI contributors.

## License

Apache-2.0 &copy; Shiv Yadav

---

### Disclaimer

**HipaaLint AI is a static analysis tool designed to assist in identifying potential PHI exposure and enforcing security best practices. It does NOT guarantee HIPAA, SOC2, GDPR, or CCPA compliance.**

This software is provided "AS IS", without warranty of any kind. The generated reports and compliance scores are for informational purposes only and should not be construed as legal or regulatory advice. Ultimate responsibility for compliance and data security remains with the developers, organizations, and covered entities using this software. Always consult with a qualified legal or compliance professional.
