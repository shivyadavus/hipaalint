#!/usr/bin/env node

import { readFileSync } from 'fs';
import { join } from 'path';
import { spawnSync } from 'child_process';

const extensionPackagePath = join('vscode-extension', 'package.json');
const extensionPackage = JSON.parse(readFileSync(extensionPackagePath, 'utf8'));
const outputPath = `../hipaalint-vscode-${extensionPackage.version}.vsix`;

const result = spawnSync('npx', ['@vscode/vsce', 'package', '-o', outputPath], {
  cwd: 'vscode-extension',
  stdio: 'inherit',
});

if (result.status !== 0) {
  process.exit(result.status ?? 1);
}
