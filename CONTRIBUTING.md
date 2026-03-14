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
   npm run format:check && npm run typecheck && npm run lint && npm test
   ```
5. Open a pull request against `main` using the [PR template](./.github/PULL_REQUEST_TEMPLATE.md)

### Commit & PR Guidelines

- **Commit messages**: Use imperative mood, be concise (e.g., "Add PHI detection for MRN patterns", not "Added PHI detection")
- **PR titles**: Use a descriptive title that summarizes the change (e.g., "Add network segmentation rule HIPAA-INF-004")
- **One concern per PR**: Keep pull requests focused — avoid bundling unrelated changes
- **Reference issues**: Link related issues in your PR description (e.g., "Fixes #42")

### Pre-Commit Hook

The repository includes a pre-commit hook that blocks commits containing critical HIPAA violations. Install it after cloning:

```bash
cp hooks/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit
```

This runs automatically on every commit to prevent PHI exposure in source code.

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

## Review Process

All contributions go through the following review process:

1. **CI checks**: Your PR must pass `typecheck`, `lint`, `format:check`, and `test` before review
2. **Maintainer review**: At least one maintainer must approve the PR
3. **PHI scrutiny**: Changes touching PHI detection, scoring, or report generation receive additional review for accuracy and safety
4. **Squash merge**: PRs are squash-merged into `main` to keep history clean

Maintainers aim to review PRs within **3 business days**. If your PR hasn't received feedback after that, feel free to leave a comment.

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](./LICENSE).
