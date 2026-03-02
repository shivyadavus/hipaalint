<div align="center">

# 🛡️ HipaaLint AI

**HIPAA compliance enforcement for AI-assisted development**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)

*Automatically detect PHI exposure, enforce HIPAA controls, and generate compliance audit reports — all from your terminal or AI coding agent.*

</div>

---

## 🚀 Quick Start

```bash
# Install globally
npm install -g @hipaalint/ai

# Scan your project
hipaalint scan .

# Get your HipaaLint Score
hipaalint score .

# Generate a PDF audit report  
hipaalint report . --format pdf
```

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **PHI Detection** | Detects all 18 HIPAA identifiers (SSN, DOB, MRN, email, phone, etc.) |
| 📊 **HipaaLint Score** | Weighted 0-100 score across 6 compliance domains |
| 📋 **29 HIPAA Rules** | Pre-seeded rule database with regex, AST, and import patterns |
| 📄 **Audit Reports** | JSON, SARIF, and PDF reports with executive summaries |
| 🤖 **MCP Server** | 5 tools for Claude Code, Cursor, and other AI agents |
| ⚡ **GitHub Action** | CI/CD integration with SARIF upload and score thresholds |
| 🔒 **Pre-Commit Hook** | Block commits with critical HIPAA violations |
| 🏷️ **Score Badge** | shields.io badge for your README |

## 📊 The 6 Compliance Domains

HipaaLint evaluates your codebase across weighted domains:

| Domain | Weight | What It Checks |
|--------|--------|----------------|
| PHI Protection | 25% | PHI in source code, logs, error handlers, API responses |
| Encryption | 20% | TLS/HTTPS enforcement, strong hashing, no hardcoded keys |
| Access Control | 20% | Auth middleware, RBAC, input validation |
| Audit Logging | 15% | Structured audit trails, log integrity |
| Infrastructure | 10% | CORS security, helmet headers, rate limiting |
| AI Governance | 10% | PHI scrubbing for AI prompts, model input sanitization |

## 🛠️ CLI Commands

### `hipaalint scan [path]`
Scan a project for HIPAA violations:
```bash
hipaalint scan ./src --sensitivity strict --framework hipaa
```

### `hipaalint score [path]`
Calculate the HipaaLint Score:
```bash
hipaalint score . --threshold 80  # Fail CI if below 80
```

### `hipaalint report [path]`
Generate audit reports:
```bash
hipaalint report . --format pdf --output ./reports
hipaalint report . --format sarif  # For GitHub Code Scanning
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
```

## 🤖 AI Agent Integration (MCP)

HipaaLint runs as an MCP server, giving AI coding agents 5 compliance tools:

```json
// .mcp.json
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
- `compliance_report` — Generate audit reports
- `phi_detect` — Detect PHI in code snippets
- `compliance_rules` — Search rule database

## ⚡ GitHub Action

```yaml
# .github/workflows/compliance.yml
name: Compliance Check
on: [push, pull_request]

jobs:
  hipaa:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: shivyadavus/hipaalint-ai@v1
        with:
          threshold: 70
          sensitivity: balanced
          upload-sarif: true
```

## 🔒 Pre-Commit Hook

```bash
cp node_modules/@hipaalint/ai/hooks/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit
```

Blocks commits with critical HIPAA violations. Warns on high-severity findings.

## 📊 Score Badge

Add to your README:
```markdown
[![HipaaLint Score](https://img.shields.io/badge/HipaaLint-92%2F100-00c853?style=for-the-badge)](https://github.com/your-org/your-repo)
```

## 🏗️ Architecture

```
src/
├── engine/           # Core analysis engine
│   ├── types.ts      # Zod-validated type system
│   ├── phi-detector.ts    # 18 HIPAA identifier detectors
│   ├── rule-evaluator.ts  # Pattern matching engine (5 types)
│   └── score-calculator.ts # Weighted scoring algorithm
├── rules/            # Rule database
│   └── db/           # SQLite schema + HIPAA seed data
├── mcp-server/       # MCP server (5 tools)
├── cli/              # CLI entry point (commander.js)
└── reports/          # JSON, SARIF, PDF generators
```

## 📋 Supported Identifiers (18 HIPAA PHI Types)

Names, SSN, DOB, Addresses, Phone Numbers, Email, Medical Record Numbers, Health Plan IDs, Account Numbers, Certificate/License Numbers, Vehicle Identifiers, Device IDs, Web URLs, IP Addresses, Biometric IDs, Photos, Geographic Data (ZIP codes), and Dates.

## 🤝 Contributing

Contributions are welcome! Please read our [AGENTS.md](./AGENTS.md) for coding guidelines that apply to both human and AI contributors.

## 📄 License

Apache-2.0 © Shiv Yadav

---

## ⚠️ Legal Disclaimer

**HipaaLint AI is a static analysis tool designed to assist in identifying potential PHI exposure and enforcing security best practices. It does NOT guarantee HIPAA, SOC2, GDPR, or CCPA compliance.** 

This software is provided "AS IS", without warranty of any kind. The generated reports and compliance scores are for informational purposes only and should not be construed as legal or regulatory advice. Ultimate responsibility for compliance and data security remains with the developers, organizations, and covered entities using this software. Always consult with a qualified legal or compliance professional.
