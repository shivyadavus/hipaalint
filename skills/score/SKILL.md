---
name: score
description: >
  Calculate the HipaaLint compliance score for a project. Returns a weighted
  0-100 score across 6 HIPAA domains (PHI Protection, Encryption, Access Control,
  Audit Logging, Infrastructure, AI Governance) with band classification.
user-invocable: true
argument-hint: '[path] [--sensitivity strict|balanced|relaxed]'
allowed-tools: Read, Grep, Glob, Bash
---

# /score

Calculate the HipaaLint Score for the current project.

## Usage

```
/hipaalint-ai:score [path] [--sensitivity balanced] [--threshold 70]
```

## Parameters

- `path` — Directory to evaluate (default: current project root)
- `--sensitivity` — Detection sensitivity: `strict`, `balanced` (default), `relaxed`
- `--threshold` — Fail if score is below this value (default: 0, no threshold)

## What It Does

1. Runs a full compliance scan across all source files
2. Calculates a weighted score (0-100) across 6 HIPAA domains:
   - PHI Protection (25%)
   - Encryption (20%)
   - Access Control (20%)
   - Audit Logging (15%)
   - Infrastructure (10%)
   - AI Governance (10%)
3. Applies severity penalties: critical=15, high=8, medium=3, low=1
4. Applies clamping rules for critical gaps (e.g., critical PHI exposure caps at 69)
5. Returns overall score with band classification

## Score Bands

| Band              | Score  | Meaning                                               |
| ----------------- | ------ | ----------------------------------------------------- |
| Strong            | 90-100 | Meets baseline HIPAA technical safeguard requirements |
| Needs Improvement | 70-89  | Minor gaps to address                                 |
| At Risk           | 50-69  | Significant compliance gaps                           |
| Critical          | 0-49   | Major violations requiring immediate action           |

## Example Output

```
HipaaLint Score

  Overall: 78/100 (needs improvement)

  Domain Breakdown:
    PHI Protection:  85/100 (25% weight)
    Encryption:      90/100 (20% weight)
    Access Control:  65/100 (20% weight)
    Audit Logging:   70/100 (15% weight)
    Infrastructure:  80/100 (10% weight)
    AI Governance:   75/100 (10% weight)
```

## MCP Tool

This skill invokes the `compliance_score` MCP tool.
