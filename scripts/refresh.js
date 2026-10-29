#!/usr/bin/env node
import { openDb, listAllForRefresh, upsertEntry, recordFailure } from '../src/db.js';
import { verifySite } from '../src/site.js';

const dbPath = process.env.DATABASE_PATH || 'data/directory.db';
const allowInsecure = process.env.ALLOW_INSECURE === '1';
const allowPrivate = process.env.ALLOW_PRIVATE_HOSTS === '1';
const timeoutMs = Number(process.env.REFRESH_TIMEOUT_MS || 8000);
const concurrency = Math.min(Math.max(Number(process.env.REFRESH_CONCURRENCY || 5), 1), 16);

const db = openDb(dbPath);
const rows = listAllForRefresh(db);
console.log(`[refresh] checking ${rows.length} entries from ${dbPath}`);

let updated = 0;
let failed = 0;
let index = 0;

async function worker() {
  while (index < rows.length) {
    const current = index;
    index += 1;
    const row = rows[current];
    try {
      const site = await verifySite(row.site_url, { allowInsecure, allowPrivate, timeoutMs });
      if (site.did !== row.did) {
        throw new Error('the site now publishes a different did:web identity');
      }
      upsertEntry(db, site);
      updated += 1;
    } catch (err) {
      const message = err && err.message ? err.message : String(err);
      recordFailure(db, row, message);
      failed += 1;
      console.error(`[refresh] ${row.site_url}: ${message}`);
    }
  }
}

await Promise.all(Array.from({ length: Math.min(concurrency, rows.length) }, worker));

console.log(`[refresh] done: ${updated} updated, ${failed} failed, ${rows.length - updated - failed} untouched`);
db.close();
