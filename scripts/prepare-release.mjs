#!/usr/bin/env node

import { execFileSync } from 'child_process';
import { readFileSync, writeFileSync } from 'fs';

const args = process.argv.slice(2);
const syncOnly = args.includes('--sync-only');
const bumpArg = args.find((arg) => !arg.startsWith('--'));

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function updateJetBrainsVersion(version) {
  const buildGradlePath = 'jetbrains-plugin/build.gradle';
  const buildGradle = readFileSync(buildGradlePath, 'utf8');
  if (!/^version = '.*'$/m.test(buildGradle)) {
    throw new Error('Failed to update JetBrains plugin version in build.gradle');
  }

  const next = buildGradle.replace(/^version = '.*'$/m, `version = '${version}'`);
  writeFileSync(buildGradlePath, next);
}

if (!syncOnly) {
  if (!bumpArg) {
    console.error('Usage: npm run release:prepare -- <patch|minor|major|x.y.z> [--sync-only]');
    process.exit(1);
  }

  execFileSync('npm', ['version', bumpArg, '--no-git-tag-version'], {
    stdio: 'inherit',
  });
}

const rootPackage = readJson('package.json');
const version = rootPackage.version;

const claudePlugin = readJson('.claude-plugin/plugin.json');
claudePlugin.version = version;
writeJson('.claude-plugin/plugin.json', claudePlugin);

const claudeMarketplace = readJson('.claude-plugin/marketplace.json');
claudeMarketplace.metadata.version = version;
if (Array.isArray(claudeMarketplace.plugins)) {
  claudeMarketplace.plugins = claudeMarketplace.plugins.map((plugin) => ({
    ...plugin,
    version,
  }));
}
writeJson('.claude-plugin/marketplace.json', claudeMarketplace);

const vscodeExtension = readJson('vscode-extension/package.json');
vscodeExtension.version = version;
writeJson('vscode-extension/package.json', vscodeExtension);

updateJetBrainsVersion(version);

console.log(`Synchronized release version ${version}`);
