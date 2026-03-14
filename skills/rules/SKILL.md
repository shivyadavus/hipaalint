---
name: rules
description: >
  List and search compliance rules in the HipaaLint database. Browse all 266 rules
  across HIPAA, HITRUST CSF, and SOC 2 Health in 6 categories. Filter by severity
  or category, and search by keyword. Each rule includes citations and remediation guidance.
user-invocable: true
argument-hint: '[--category phi_protection] [--severity critical] [--query keyword]'
allowed-tools: Read, Grep, Glob, Bash
---

# /rules

List and search HIPAA compliance rules.

## Usage

```
/hipaalint-ai:rules [--category phi_protection] [--severity critical] [--query keyword]
```

## Parameters

- `--category` — Filter by category: `phi_protection`, `encryption`, `access_control`, `audit_logging`, `infrastructure`, `ai_governance`
- `--severity` — Filter by severity: `critical`, `high`, `medium`, `low`
- `--query` — Search rules by keyword (searches title, description, and tags)

## What It Does

1. Queries the HipaaLint rule database (266 rules across HIPAA, HITRUST CSF, and SOC 2 Health)
2. Applies optional filters by category, severity, or keyword
3. Returns matching rules with ID, title, severity, category, and description

## Rule Categories

| Category         | Rule Prefixes                                    | Description                             |
| ---------------- | ------------------------------------------------ | --------------------------------------- |
| `phi_protection` | HIPAA-PHI-\*, HITRUST-PHI-\*, SOC2H-PHI-\*       | Protected Health Information safeguards |
| `encryption`     | HIPAA-ENC-\*, HITRUST-ENC-\*, SOC2H-ENC-\*       | Encryption and data-in-transit/at-rest  |
| `access_control` | HIPAA-AC-\*, HITRUST-AC-\*, SOC2H-AC-\*          | Authentication and authorization        |
| `audit_logging`  | HIPAA-LOG-\*, HITRUST-LOG-\*, SOC2H-LOG-\*       | Audit trail and monitoring              |
| `infrastructure` | HIPAA-INFRA-\*, HITRUST-INFRA-\*, SOC2H-INFRA-\* | Infrastructure security controls        |
| `ai_governance`  | HIPAA-AI-\*, HITRUST-AI-\*, SOC2H-AI-\*          | AI/ML model governance                  |

## Example Output

```
HipaaLint Rules (266)

  HIPAA-PHI-001: PHI in Log Statements
    Severity: critical | Category: phi_protection
    Detects Protected Health Information written to application logs

  HIPAA-ENC-001: Unencrypted HTTP Usage
    Severity: critical | Category: encryption
    Detects HTTP URLs that should use HTTPS for data in transit

  HIPAA-AC-001: Missing Auth Middleware
    Severity: high | Category: access_control
    Detects API routes handling PHI without authentication middleware
```

## MCP Tool

This skill invokes the `compliance_rules` MCP tool.
