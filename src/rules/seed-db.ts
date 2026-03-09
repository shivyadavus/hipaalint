#!/usr/bin/env tsx
/**
 * Reset and seed the HipaaLint database with the full bundled rule catalog.
 *
 * Usage: npx tsx src/rules/seed-db.ts [dbPath]
 */

import { RuleDatabase } from './rule-loader.js';

const dbPath = process.argv[2];
const db = new RuleDatabase(dbPath);

console.log('Resetting and seeding HipaaLint database...');
db.resetAndSeed();

const ruleCount = db.getRuleCount();
console.log(`✅ Database seeded with ${ruleCount} rules`);

db.close();
