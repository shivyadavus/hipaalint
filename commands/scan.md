# /compliance:scan

Scan the current project for HIPAA compliance violations.

## Usage
```
/compliance:scan [path] [--framework hipaa] [--sensitivity balanced]
```

## Parameters
- `path` — Directory to scan (default: current project root)
- `--framework` — Compliance framework: `hipaa` (default)
- `--sensitivity` — Detection sensitivity: `strict`, `balanced` (default), `relaxed`

## What It Does
1. Scans all source files for PHI exposure patterns
2. Evaluates code against HIPAA Security Rule requirements
3. Checks encryption, access control, audit logging, and infrastructure
4. Returns findings grouped by severity (critical → info)

## Example Output
```
HipaaLint Scan Results
─────────────────────────────
Files scanned: 47  |  Rules evaluated: 29

🔴 CRITICAL (2)
  HIPAA-PHI-001  PHI in Log Statements     src/services/patient.ts:45
  HIPAA-ENC-001  Unencrypted HTTP Usage     src/api/client.ts:12

🟡 HIGH (3)
  HIPAA-PHI-005  IP Address in Logs         src/middleware/logger.ts:23
  HIPAA-AC-001   Missing Auth Middleware    src/routes/patients.ts:8
  HIPAA-ENC-002  Weak Hashing Algorithm     src/auth/password.ts:15
```

## MCP Tool
This command invokes the `compliance_scan` MCP tool.
