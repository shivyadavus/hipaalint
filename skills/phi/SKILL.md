---
name: phi
description: >
  Detect Protected Health Information (PHI) in code files. Identifies 18 HIPAA
  identifier types including names, SSNs, medical record numbers, dates of birth,
  and IP addresses in source code, logs, and configuration files.
user-invocable: true
argument-hint: '<file> [--sensitivity strict|balanced|relaxed]'
allowed-tools: Read, Grep, Glob, Bash
---

# /phi

Detect Protected Health Information (PHI) in a file or code snippet.

## Usage

```
/hipaalint-ai:phi <file> [--sensitivity balanced]
```

## Parameters

- `file` — File path to scan for PHI (required)
- `--sensitivity` — Detection sensitivity: `strict`, `balanced` (default), `relaxed`

## What It Does

1. Scans the specified file for PHI exposure patterns
2. Detects 18 HIPAA identifier types across two detection methods:
   - **Regex patterns** (8 types): SSN, email, phone, date of birth, IP address, MRN, credit card, ZIP code
   - **Variable name patterns** (9 types): patient name, DOB, SSN, MRN, address, phone, email, diagnosis, insurance ID
3. Returns each detection with confidence level, line/column location, context, and HIPAA citation

## HIPAA Identifier Types

| Type          | Example Pattern       | HIPAA Reference            |
| ------------- | --------------------- | -------------------------- |
| SSN           | `123-45-6789`         | 45 CFR 164.514(b)(2)(i)(L) |
| Email         | `patient@example.com` | 45 CFR 164.514(b)(2)(i)(G) |
| Phone         | `(555) 123-4567`      | 45 CFR 164.514(b)(2)(i)(F) |
| Date of Birth | `1990-01-15`          | 45 CFR 164.514(b)(2)(i)(C) |
| IP Address    | `192.168.1.1`         | 45 CFR 164.514(b)(2)(i)(O) |
| MRN           | `MRN-12345`           | 45 CFR 164.514(b)(2)(i)(E) |

## Example Output

```
PHI Detection Results - src/services/patient.ts

  Found 3 potential PHI exposure(s):

  * SSN (high confidence)
    Line 45, Col 12 | Context: const ssn = "123-45-6789"
    45 CFR 164.514(b)(2)(i)(L)

  * patient_name variable (medium confidence)
    Line 23, Col 8 | Context: const patient_name = req.body.name
    45 CFR 164.514(b)(2)(i)(A)
```

## MCP Tool

This skill invokes the `phi_detect` MCP tool.
