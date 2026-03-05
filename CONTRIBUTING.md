# Contributing to HipaaLint

Thanks for your interest in contributing to HipaaLint! This guide will help you get started.

## Getting Started

### Prerequisites

- Node.js 18+
- npm 9+

### Setup

```bash
git clone https://github.com/shivyadavus/hipaalint.git
cd hipaalint
npm install
npm run build
npm test
```

### Development Workflow

```bash
npm run dev          # Watch mode (auto-restart MCP server)
npm run cli          # Run CLI from source (tsx)
npm run test:watch   # Run tests in watch mode
npm run typecheck    # Type-check without emitting
npm run lint         # ESLint (0 warnings allowed)
npm run format       # Prettier formatting
```

## How to Contribute

### Reporting Bugs

Open a [bug report](https://github.com/shivyadavus/hipaalint/issues/new?template=bug_report.yml) with:

- Steps to reproduce
- Expected vs actual behavior
- Node.js version and OS

### Suggesting Features

Open a [feature request](https://github.com/shivyadavus/hipaalint/issues/new?template=feature_request.yml) with:

- Use case description
- Proposed solution
- Alternatives considered

### Submitting Code

1. Fork the repo and create a feature branch: `feat/your-feature`
2. Follow the coding standards in [AGENTS.md](./AGENTS.md)
3. Write tests for new functionality
4. Ensure all checks pass:
   ```bash
   npm run typecheck && npm run lint && npm test
   ```
5. Open a pull request against `main`

## Coding Standards

All coding standards are documented in [AGENTS.md](./AGENTS.md). Key points:

- **Strict TypeScript** — No `any` types
- **Zod validation** — All external inputs validated via Zod schemas
- **No PHI in logs** — Never log PHI, even in tests
- **ESM only** — `import`/`export`, no `require()`
- **kebab-case** — All source files use kebab-case naming
- **Close resources** — Always call `.close()` on `RuleEvaluator` in `finally` blocks

## Adding a New Rule

1. Add the rule to `src/rules/db/seed-hipaa.sql`
2. Add detection logic in `src/engine/rule-evaluator.ts`
3. Add tests in `tests/unit/rule-evaluator.test.ts`
4. Run `npm run db:seed` to reload the rule database
5. Run the full test suite

## Project Structure

See [AGENTS.md](./AGENTS.md) for the full architecture breakdown.

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](./LICENSE).
