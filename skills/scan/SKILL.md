---
name: scan
description: >
  Scan a project directory for HIPAA compliance violations. Detects PHI exposure,
  encryption gaps, access control issues, and audit logging gaps. Returns findings
  grouped by severity with HIPAA citations and remediation guidance.
user-invocable: true
argument-hint: "[path] [--sensitivity strict|balanced|relaxed]"
allowed-tools: Read, Grep, Glob, Bash
---

# /scan

Scan the current project for HIPAA compliance violations.

## Usage

```
/hipaalint-ai:scan [path] [--sensitivity balanced]
```

## Parameters

- `path` — Directory to scan (default: current project root)
- `--sensitivity` — Detection sensitivity: `strict`, `balanced` (default), `relaxed`

## What It Does

1. Scans all source files for PHI exposure patterns
2. Evaluates code against 33 HIPAA Security Rule requirements
3. Checks encryption, access control, audit logging, and infrastructure
4. Returns findings grouped by severity (critical, high, medium, low)

## Example Output

```
HipaaLint Scan Results
Files scanned: 47  |  Rules evaluated: 33

CRITICAL (2)
  HIPAA-PHI-001  PHI in Log Statements     src/services/patient.ts:45
  HIPAA-ENC-001  Unencrypted HTTP Usage     src/api/client.ts:12

HIGH (3)
  HIPAA-PHI-005  IP Address in Logs         src/middleware/logger.ts:23
  HIPAA-AC-001   Missing Auth Middleware    src/routes/patients.ts:8
  HIPAA-ENC-002  Weak Hashing Algorithm     src/auth/password.ts:15
```

Each finding includes the HIPAA citation (e.g., 45 CFR §164.312(e)(1)) and actionable remediation.

## Auto-Fix

Add `--fix` to auto-remediate simple violations:

```
/hipaalint-ai:scan [path] --fix --dry-run   # preview changes
/hipaalint-ai:scan [path] --fix             # apply fixes
```

## MCP Tool

This skill invokes the `compliance_scan` MCP tool.
