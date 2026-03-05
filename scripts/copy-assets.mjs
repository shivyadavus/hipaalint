#!/usr/bin/env node

/**
 * Cross-platform asset copier — replaces Unix-only `cp -r`.
 * Copies src/rules/db/*.sql to dist/rules/db/.
 */

import { cpSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';

const src = join('src', 'rules', 'db');
const dest = join('dist', 'rules', 'db');

if (!existsSync(src)) {
  console.warn(`Warning: source directory ${src} not found, skipping asset copy.`);
  process.exit(0);
}

mkdirSync(dest, { recursive: true });
cpSync(src, dest, { recursive: true });

console.log(`Copied ${src} → ${dest}`);
