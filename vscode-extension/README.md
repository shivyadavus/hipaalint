# HipaaLint for VS Code

Inline HIPAA, HITRUST, and SOC 2 diagnostics for healthcare codebases.

## Features

- Real-time diagnostics for supported JavaScript, TypeScript, and Python files
- Quick fixes for insecure HTTP, weak TLS, and wildcard CORS
- Workspace compliance dashboard with score and finding summary
- Status bar score band updates
- Settings integration with `.hipaalintrc`

## Development

From the repository root:

```bash
npm run build
npm run vscode:compile
npm run vscode:package
```
