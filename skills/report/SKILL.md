---
name: report
description: >
  Generate a HIPAA compliance audit report for a project. Produces JSON, SARIF,
  or PDF reports with executive summary, scored findings, domain breakdown,
  and prioritized remediation recommendations.
user-invocable: true
argument-hint: '[path] [--format json|pdf|sarif]'
allowed-tools: Read, Grep, Glob, Bash
---

# /report

Generate a compliance audit report for the current project.

## Usage

```
/hipaalint-ai:report [path] [--format json] [--output ./report]
```

## Parameters

- `path` — Directory to report on (default: current project root)
- `--format` — Output format: `json` (default), `pdf`, or `sarif`
- `--output` — Output file path (default: `./hipaalint-report`)

## What It Does

1. Runs a full compliance scan across all source files
2. Calculates the HipaaLint Score (0-100, weighted across 6 domains)
3. Generates a structured report with:
   - Executive summary with score band
   - All findings with HIPAA citations and remediation guidance
   - Domain-by-domain breakdown (PHI, Encryption, Access Control, Audit, Infrastructure, AI)
   - Prioritized recommendations

## Output Formats

| Format  | Use Case                            |
| ------- | ----------------------------------- |
| `json`  | Machine-readable, CI/CD integration |
| `sarif` | GitHub Code Scanning upload         |
| `pdf`   | Auditor-ready 5-page report         |

## MCP Tool

This skill invokes the `compliance_report` MCP tool.
