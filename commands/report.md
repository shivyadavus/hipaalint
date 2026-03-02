# /compliance:report

Generate a compliance audit report for the current project.

## Usage
```
/compliance:report [path] [--format json|pdf] [--output ./report]
```

## Parameters
- `path` — Directory to report on (default: current project root)
- `--format` — Output format: `json` (default) or `pdf`
- `--output` — Output file path (default: `./hipaalint-report`)

## What It Does
1. Runs a full compliance scan
2. Calculates the HipaaLint Score
3. Generates a structured report with:
   - Executive summary with score band
   - All findings with citations and remediation guidance
   - Domain-by-domain breakdown
   - Prioritized recommendations

## MCP Tool
This command invokes the `compliance_report` MCP tool.
