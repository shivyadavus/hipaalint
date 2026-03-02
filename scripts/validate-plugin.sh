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
  if python3 -c "import json; json.load(open('$PLUGIN_FILE'))" 2>/dev/null || \
     node -e "JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8'))" 2>/dev/null; then
    pass "Valid JSON"
  else
    fail "Invalid JSON in $PLUGIN_FILE"
  fi

  # Check required fields
  NAME=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8')).name || '')" 2>/dev/null)
  VERSION=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8')).version || '')" 2>/dev/null)
  DESC=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8')).description || '')" 2>/dev/null)

  [ -n "$NAME" ] && pass "name: $NAME" || fail "Missing 'name' field"
  [ -n "$VERSION" ] && pass "version: $VERSION" || fail "Missing 'version' field"
  [ -n "$DESC" ] && pass "description present" || warn "Missing 'description' field"

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
fi

echo ""

# ── 2. Referenced files ─────────────────────────
echo "📂 Checking referenced files..."

# Skills
for skill in $(node -e "const p=JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8')); (p.skills||[]).forEach(s=>console.log(s))" 2>/dev/null); do
  [ -f "$skill" ] && pass "skill: $skill" || fail "Missing skill: $skill"
done

# Commands
for cmd in $(node -e "const p=JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8')); (p.commands||[]).forEach(c=>console.log(c))" 2>/dev/null); do
  [ -f "$cmd" ] && pass "command: $cmd" || fail "Missing command: $cmd"
done

# Agents
for agent in $(node -e "const p=JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8')); (p.agents||[]).forEach(a=>console.log(a))" 2>/dev/null); do
  [ -f "$agent" ] && pass "agent: $agent" || fail "Missing agent: $agent"
done

echo ""

# ── 3. MCP configuration ───────────────────────
echo "🔌 Checking MCP configuration..."

MCP_REF=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$PLUGIN_FILE','utf8')).mcp || '')" 2>/dev/null)
if [ -n "$MCP_REF" ]; then
  # Resolve relative to .claude-plugin/
  MCP_PATH=$(cd .claude-plugin && realpath "$MCP_REF" 2>/dev/null || echo "")
  if [ -f "$MCP_PATH" ]; then
    pass "MCP config: $MCP_PATH"

    # Check that the MCP server entry point exists (after build)
    SERVER_PATH=$(node -e "const m=JSON.parse(require('fs').readFileSync('$MCP_PATH','utf8')); const srv=Object.values(m.mcpServers||{})[0]; console.log((srv?.args||[])[0]||'')" 2>/dev/null)
    if [ -n "$SERVER_PATH" ] && [ -f "$SERVER_PATH" ]; then
      pass "MCP server entry: $SERVER_PATH"
    elif [ -n "$SERVER_PATH" ]; then
      warn "MCP server entry not found: $SERVER_PATH (run 'npm run build' first)"
    fi
  else
    fail "MCP config not found: $MCP_REF (resolved: $MCP_PATH)"
  fi
else
  warn "No MCP server referenced in plugin.json"
fi

# Check .mcp.json at root
if [ -f ".mcp.json" ]; then
  pass ".mcp.json exists at root"
else
  warn "No .mcp.json at project root"
fi

echo ""

# ── 4. Package structure ──────────────────────
echo "📦 Checking package structure..."

[ -f "package.json" ] && pass "package.json" || fail "Missing package.json"
[ -f "README.md" ] && pass "README.md" || fail "Missing README.md"
[ -f "AGENTS.md" ] && pass "AGENTS.md" || warn "Missing AGENTS.md"
[ -f "tsconfig.json" ] && pass "tsconfig.json" || warn "Missing tsconfig.json"

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

# ── 5. Summary ──────────────────────────────────
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
