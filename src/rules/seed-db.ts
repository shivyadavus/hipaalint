#!/usr/bin/env tsx
/**
 * Seed the HipaaLint database with HIPAA rules.
 * Use this to reset and re-seed the database.
 *
 * Usage: npx tsx src/rules/seed-db.ts [dbPath]
 */

import { RuleDatabase } from './rule-loader.js';

const dbPath = process.argv[2];
const db = new RuleDatabase(dbPath);

console.log('Seeding HipaaLint database with HIPAA rules...');
db.initSchema();
db.seedHIPAA();

const ruleCount = db.getRuleCount();
console.log(`✅ Database seeded with ${ruleCount} HIPAA rules`);

db.close();
