#!/usr/bin/env bash
# ─────────────────────────────────────────────────────
# publish-plugin.sh — Release and publish HipaaLint AI
#
# Usage:
#   bash scripts/publish-plugin.sh patch   # 0.1.0 → 0.1.1
#   bash scripts/publish-plugin.sh minor   # 0.1.0 → 0.2.0
#   bash scripts/publish-plugin.sh major   # 0.1.0 → 1.0.0
# ─────────────────────────────────────────────────────

set -euo pipefail

BUMP=${1:-patch}

echo "═══════════════════════════════════════════"
echo "  HipaaLint AI — Release Pipeline"
echo "═══════════════════════════════════════════"
echo ""

# ── 1. Pre-flight checks ───────────────────────
echo "🔍 Pre-flight checks..."

# Ensure clean working tree
if [ -n "$(git status --porcelain)" ]; then
  echo "❌ Working tree is not clean. Commit or stash changes first."
  exit 1
fi

# Ensure on main branch
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
  echo "❌ Must be on main branch (currently on $BRANCH)"
  exit 1
fi

# Ensure tests pass
echo "  Running tests..."
npm run test
echo "  ✅ Tests passed"

# Ensure build works
echo "  Building..."
npm run build
echo "  ✅ Build succeeded"

# Validate plugin
echo "  Validating plugin..."
bash scripts/validate-plugin.sh
echo ""

# ── 2. Version bump ────────────────────────────
echo "📦 Bumping version ($BUMP)..."

# Bump package.json version (no git tag yet)
NEW_VERSION=$(npm version "$BUMP" --no-git-tag-version | tr -d 'v')
echo "  New version: $NEW_VERSION"

# Sync version in plugin metadata
node -e "
const fs = require('fs');
const pluginPath = '.claude-plugin/plugin.json';
const plugin = JSON.parse(fs.readFileSync(pluginPath, 'utf8'));
plugin.version = '$NEW_VERSION';
fs.writeFileSync(pluginPath, JSON.stringify(plugin, null, 4) + '\n');

const marketplacePath = '.claude-plugin/marketplace.json';
const marketplace = JSON.parse(fs.readFileSync(marketplacePath, 'utf8'));
marketplace.metadata.version = '$NEW_VERSION';
if (Array.isArray(marketplace.plugins)) {
  marketplace.plugins = marketplace.plugins.map((entry) => ({
    ...entry,
    version: '$NEW_VERSION'
  }));
}
fs.writeFileSync(marketplacePath, JSON.stringify(marketplace, null, 4) + '\n');

console.log('  ✅ plugin.json updated to $NEW_VERSION');
console.log('  ✅ marketplace.json updated to $NEW_VERSION');
"

# ── 3. Rebuild with new version ────────────────
echo "  Rebuilding with new version..."
npm run build

# ── 4. Commit & Tag ────────────────────────────
echo ""
echo "🏷️  Creating release commit and tag..."

git add package.json package-lock.json .claude-plugin/plugin.json .claude-plugin/marketplace.json
git commit -m "release: v${NEW_VERSION}"
git tag -a "v${NEW_VERSION}" -m "Release v${NEW_VERSION}"

echo "  ✅ Tagged v${NEW_VERSION}"

# ── 5. Push ────────────────────────────────────
echo ""
echo "🚀 Pushing to origin..."

git push origin main
git push origin "v${NEW_VERSION}"

echo ""
echo "═══════════════════════════════════════════"
echo "  ✅ Released v${NEW_VERSION}"
echo ""
echo "  The tag push will trigger:"
echo "    • npm publish via .github/workflows/release.yml"
echo "    • GitHub Release with changelog"
echo ""
echo "  To install as Claude Code plugin:"
echo "    claude plugin install https://github.com/shivyadavus/hipaalint"
echo ""
echo "  To submit to Claude Code marketplace:"
echo "    1. Go to claude.com → Settings → Plugins → Submit"
echo "    2. Enter repo URL: https://github.com/shivyadavus/hipaalint"
echo "═══════════════════════════════════════════"
