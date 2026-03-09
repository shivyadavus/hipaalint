#!/usr/bin/env node

/**
 * Cross-platform asset copier for immutable SQL seed assets.
 */

import { copyFileSync, existsSync, mkdirSync, readdirSync, rmSync } from 'fs';
import { extname, join } from 'path';

const src = join('src', 'rules', 'db');
const dest = join('dist', 'rules', 'db');

if (!existsSync(src)) {
  console.warn(`Warning: source directory ${src} not found, skipping asset copy.`);
  process.exit(0);
}

rmSync(dest, { recursive: true, force: true });
mkdirSync(dest, { recursive: true });

for (const entry of readdirSync(src, { withFileTypes: true })) {
  if (!entry.isFile() || extname(entry.name) !== '.sql') {
    continue;
  }

  copyFileSync(join(src, entry.name), join(dest, entry.name));
}

console.log(`Copied ${src} → ${dest}`);
