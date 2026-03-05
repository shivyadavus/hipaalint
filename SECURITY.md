# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in HipaaLint, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please use one of these methods:

1. **GitHub Security Advisories** (preferred): [Report a vulnerability](https://github.com/shivyadavus/hipaalint/security/advisories/new)
2. **Email**: Send details to the maintainer via the contact information on [the author's GitHub profile](https://github.com/shivyadavus)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix or mitigation**: Varies by severity, targeting:
  - Critical: 7 days
  - High: 14 days
  - Medium/Low: Next release cycle

## Security Scope

HipaaLint is a **static analysis tool** that runs locally. Its security scope includes:

- **Input validation**: All user inputs (file paths, CLI arguments, MCP tool parameters) are validated via Zod schemas
- **Path traversal prevention**: Scan paths are validated against directory traversal attacks
- **ReDoS protection**: All regex patterns are checked for catastrophic backtracking
- **No network access**: The engine operates entirely offline with no external API calls
- **No PHI storage**: HipaaLint never stores, transmits, or logs PHI it detects

## Security Best Practices

When using HipaaLint:

- Do not commit scan reports containing PHI findings to public repositories
- Use `--json` output and pipe to secure storage for audit trails
- Review auto-fix changes (`--dry-run`) before applying to production code
- Keep HipaaLint updated to receive the latest rule definitions

## Disclaimer

HipaaLint is a static analysis tool and does **not** guarantee HIPAA compliance. It is one layer in a defense-in-depth compliance strategy. Always consult qualified legal and compliance professionals.
