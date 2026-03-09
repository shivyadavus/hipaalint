#!/usr/bin/env tsx
/**
 * Initialize the HipaaLint database.
 * Creates the schema and seeds the full bundled rule catalog.
 *
 * Usage: npx tsx src/rules/init-db.ts [dbPath]
 */

import { RuleDatabase } from './rule-loader.js';

const dbPath = process.argv[2];
const db = new RuleDatabase(dbPath);

console.log('Initializing HipaaLint database...');
db.initialize();

const ruleCount = db.getRuleCount();
const frameworks = db.getFrameworks();

console.log(`✅ Database initialized successfully`);
console.log(`   Frameworks: ${frameworks.map((f) => f.name).join(', ')}`);
console.log(`   Rules: ${ruleCount}`);

db.close();
