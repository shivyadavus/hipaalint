#!/usr/bin/env bash
# ─────────────────────────────────────────────────────
# validate-plugin.sh — Validate Claude Code plugin structure
# Run locally or in CI: bash scripts/validate-plugin.sh
# ─────────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; ERRORS=$((ERRORS + 1)); }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; WARNINGS=$((WARNINGS + 1)); }

echo "═══════════════════════════════════════════"
echo "  HipaaLint Plugin Validator"
echo "═══════════════════════════════════════════"
echo ""

# ── 1. plugin.json ──────────────────────────────
echo "📋 Checking plugin.json..."

PLUGIN_FILE=".claude-plugin/plugin.json"
if [ ! -f "$PLUGIN_FILE" ]; then
  fail "Missing $PLUGIN_FILE"
else
  pass "plugin.json exists"

  # Validate JSON
  if node -e "JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8'))" 2>/dev/null; then
    pass "Valid JSON"
  else
    fail "Invalid JSON in $PLUGIN_FILE"
  fi

  # Check required fields
  NAME=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8')).name || '')" 2>/dev/null)
  VERSION=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8')).version || '')" 2>/dev/null)
  DESC=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8')).description || '')" 2>/dev/null)
  AUTHOR=$(node -e "const a=JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8')).author; console.log(typeof a === 'object' ? a.name || '' : a || '')" 2>/dev/null)

  [ -n "$NAME" ] && pass "name: $NAME" || fail "Missing 'name' field"
  [ -n "$VERSION" ] && pass "version: $VERSION" || fail "Missing 'version' field"
  [ -n "$DESC" ] && pass "description present" || warn "Missing 'description' field"
  [ -n "$AUTHOR" ] && pass "author: $AUTHOR" || warn "Missing 'author' field"

  # Validate kebab-case name
  if echo "$NAME" | grep -qE '^[a-z][a-z0-9-]*$'; then
    pass "name is kebab-case"
  else
    fail "name '$NAME' must be kebab-case (lowercase, hyphens only)"
  fi

  # Validate semver
  if echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+'; then
    pass "version is semver"
  else
    fail "version '$VERSION' must follow semver (x.y.z)"
  fi

  # Check author is an object (marketplace requirement)
  AUTHOR_TYPE=$(node -e "const a=JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8')).author; console.log(typeof a)" 2>/dev/null)
  if [ "$AUTHOR_TYPE" = "object" ]; then
    pass "author is an object (marketplace format)"
  else
    fail "author must be an object {name, url} — not a string"
  fi
fi

echo ""

# ── 2. Skills (directory + SKILL.md) ─────────────
echo "📂 Checking skills..."

for skill_path in $(node -e "const p=JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8')); (p.skills||[]).forEach(s=>console.log(s))" 2>/dev/null); do
  # Strip leading ./
  clean_path="${skill_path#./}"
  skill_md="$clean_path/SKILL.md"
  if [ -f "$skill_md" ]; then
    pass "skill: $skill_md"
    # Check for YAML frontmatter
    if head -1 "$skill_md" | grep -q '^---'; then
      pass "  frontmatter present"
    else
      fail "  missing YAML frontmatter in $skill_md"
    fi
  else
    fail "Missing skill: $skill_md"
  fi
done

echo ""

# ── 3. Agents ──────────────────────────────────
echo "🤖 Checking agents..."

for agent_path in $(node -e "const p=JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8')); (p.agents||[]).forEach(a=>console.log(a))" 2>/dev/null); do
  clean_path="${agent_path#./}"
  if [ -f "$clean_path" ]; then
    pass "agent: $clean_path"
    # Check for YAML frontmatter
    if head -1 "$clean_path" | grep -q '^---'; then
      pass "  frontmatter present"
    else
      fail "  missing YAML frontmatter in $clean_path"
    fi
  else
    fail "Missing agent: $clean_path"
  fi
done

echo ""

# ── 4. MCP configuration ───────────────────────
echo "🔌 Checking MCP configuration..."

MCP_REF=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8')).mcpServers || '')" 2>/dev/null)
if [ -n "$MCP_REF" ]; then
  # Strip leading ./
  MCP_PATH="${MCP_REF#./}"
  if [ -f "$MCP_PATH" ]; then
    pass "MCP config: $MCP_PATH"

    # Check for ${CLAUDE_PLUGIN_ROOT} usage
    if grep -q 'CLAUDE_PLUGIN_ROOT' "$MCP_PATH"; then
      pass "Uses \${CLAUDE_PLUGIN_ROOT} for paths"
    else
      fail "MCP args must use \${CLAUDE_PLUGIN_ROOT} for portable paths"
    fi
  else
    fail "MCP config not found: $MCP_PATH"
  fi
else
  warn "No mcpServers referenced in plugin.json"
fi

echo ""

# ── 5. Marketplace manifest ────────────────────
echo "🏪 Checking marketplace.json..."

MARKET_FILE=".claude-plugin/marketplace.json"
if [ -f "$MARKET_FILE" ]; then
  pass "marketplace.json exists"
  if node -e "JSON.parse(require('fs').readFileSync('$MARKET_FILE','utf8'))" 2>/dev/null; then
    pass "Valid JSON"
  else
    fail "Invalid JSON in $MARKET_FILE"
  fi
else
  warn "Missing $MARKET_FILE (needed for marketplace distribution)"
fi

echo ""

# ── 6. Package structure ──────────────────────
echo "📦 Checking package structure..."

[ -f "package.json" ] && pass "package.json" || fail "Missing package.json"
[ -f "README.md" ] && pass "README.md" || fail "Missing README.md"
[ -f "LICENSE" ] && pass "LICENSE" || fail "Missing LICENSE"
[ -f "CHANGELOG.md" ] && pass "CHANGELOG.md" || warn "Missing CHANGELOG.md"
[ -f "AGENTS.md" ] && pass "AGENTS.md" || warn "Missing AGENTS.md"

# Check dist/ exists
if [ -d "dist" ]; then
  JS_COUNT=$(find dist -name "*.js" | wc -l | tr -d ' ')
  pass "dist/ contains $JS_COUNT JS files"
else
  warn "dist/ not found (run 'npm run build' first)"
fi

# Check SQL assets in dist
if [ -f "dist/rules/db/schema.sql" ] && [ -f "dist/rules/db/seed-hipaa.sql" ]; then
  pass "SQL assets in dist/rules/db/"
else
  warn "SQL assets missing from dist/ (run 'npm run build')"
fi

echo ""

# ── 7. Path safety ─────────────────────────────
echo "🔒 Checking path safety..."

# Ensure no paths use ../
if node -e "
  const p = JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8'));
  const paths = [...(p.skills||[]), ...(p.agents||[]), ...(p.commands||[])];
  const bad = paths.filter(s => s.includes('..'));
  if (bad.length) { console.log(bad.join(', ')); process.exit(1); }
" 2>/dev/null; then
  pass "No ../ path traversal in plugin.json"
else
  fail "plugin.json paths must not contain ../"
fi

# Ensure all paths start with ./
if node -e "
  const p = JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8'));
  const paths = [...(p.skills||[]), ...(p.agents||[])];
  const bad = paths.filter(s => !s.startsWith('./'));
  if (bad.length) { console.log(bad.join(', ')); process.exit(1); }
" 2>/dev/null; then
  pass "All paths start with ./"
else
  fail "All plugin.json paths must start with ./"
fi

echo ""

# ── Summary ──────────────────────────────────
echo "═══════════════════════════════════════════"
if [ $ERRORS -gt 0 ]; then
  echo -e "  ${RED}FAILED${NC}: $ERRORS error(s), $WARNINGS warning(s)"
  exit 1
else
  echo -e "  ${GREEN}PASSED${NC}: 0 errors, $WARNINGS warning(s)"
  echo ""
  echo "  Plugin is ready for Claude Code marketplace submission!"
  exit 0
fi
