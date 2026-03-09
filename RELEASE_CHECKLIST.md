# Release Checklist

## Goal

This project is ready to ship when the version is synchronized across all deliverables, the full release gate passes, and the release artifacts are present locally.

## Deliverables

- npm package: `@hipaalint/ai`
- Claude plugin metadata: `.claude-plugin/plugin.json`
- VS Code extension: `hipaalint-vscode-<version>.vsix`
- JetBrains plugin: `jetbrains-plugin/build/distributions/hipaalint-jetbrains-<version>.zip`

## Pre-Release

1. Confirm the working tree is clean except for intentional release changes.
2. Confirm npm, GitHub, and marketplace credentials are available but do not publish yet.
3. Confirm a supported JDK is installed or exported:
   - `JAVA_HOME`
   - or `JDK_21`
   - or `JDK_17`

## Version Prep

1. Bump and synchronize the version:

```bash
npm run release:prepare -- patch
```

2. If the root version is already correct and you only need to resync extension/plugin metadata:

```bash
npm run release:prepare -- --sync-only
```

3. Review the changed versioned files:
   - `package.json`
   - `package-lock.json`
   - `.claude-plugin/plugin.json`
   - `vscode-extension/package.json`
   - `jetbrains-plugin/build.gradle`

## Verification

Run the full local release gate:

```bash
npm run verify:release
```

Run the benchmark suite separately:

```bash
npm run test:bench
```

## Expected Artifacts

After verification, these files should exist:

```bash
ls -la hipaalint-vscode-*.vsix
find jetbrains-plugin/build/distributions -maxdepth 1 -type f
```

## Pre-Tag Review

1. Review the commit stack.
2. Confirm changelog and README messaging match the release scope.
3. Confirm CI and release workflow changes are committed.
4. Confirm no accidental generated junk is staged.

## Tag/Publish Flow

Do not run these until you want to publish.

```bash
git tag v<version>
git push origin <branch>
git push origin v<version>
```

The configured release automation is responsible for publish/package steps after tag push.

## Rollback Readiness

Before publishing, confirm:

1. Previous npm version is known.
2. Previous VSIX and JetBrains artifacts are still accessible.
3. A revert path exists for the release branch or tag.
