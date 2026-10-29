import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS entries (
  rowid INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  site_url TEXT NOT NULL UNIQUE,
  did TEXT NOT NULL UNIQUE,
  handle TEXT NOT NULL DEFAULT '',
  display_name TEXT NOT NULL,
  tagline TEXT NOT NULL DEFAULT '',
  bio TEXT NOT NULL DEFAULT '',
  location TEXT NOT NULL DEFAULT '',
  avatar_url TEXT NOT NULL DEFAULT '',
  banner_url TEXT NOT NULL DEFAULT '',
  interests_json TEXT NOT NULL DEFAULT '[]',
  interests_text TEXT NOT NULL DEFAULT '',
  links_json TEXT NOT NULL DEFAULT '[]',
  public_key_pem TEXT NOT NULL,
  profile_updated_at TEXT NOT NULL,
  verified_at TEXT NOT NULL,
  last_checked_at TEXT NOT NULL,
  fail_count INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'stale', 'blocked')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entries_status ON entries(status);
CREATE INDEX IF NOT EXISTS idx_entries_checked ON entries(last_checked_at);

CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5(
  display_name,
  handle,
  tagline,
  bio,
  location,
  interests_text,
  content='entries',
  content_rowid='rowid'
);

CREATE TRIGGER IF NOT EXISTS entries_ai AFTER INSERT ON entries BEGIN
  INSERT INTO entries_fts(rowid, display_name, handle, tagline, bio, location, interests_text)
  VALUES (new.rowid, new.display_name, new.handle, new.tagline, new.bio, new.location, new.interests_text);
END;

CREATE TRIGGER IF NOT EXISTS entries_ad AFTER DELETE ON entries BEGIN
  INSERT INTO entries_fts(entries_fts, rowid, display_name, handle, tagline, bio, location, interests_text)
  VALUES ('delete', old.rowid, old.display_name, old.handle, old.tagline, old.bio, old.location, old.interests_text);
END;

CREATE TRIGGER IF NOT EXISTS entries_au AFTER UPDATE ON entries BEGIN
  INSERT INTO entries_fts(entries_fts, rowid, display_name, handle, tagline, bio, location, interests_text)
  VALUES ('delete', old.rowid, old.display_name, old.handle, old.tagline, old.bio, old.location, old.interests_text);
  INSERT INTO entries_fts(rowid, display_name, handle, tagline, bio, location, interests_text)
  VALUES (new.rowid, new.display_name, new.handle, new.tagline, new.bio, new.location, new.interests_text);
END;

CREATE TABLE IF NOT EXISTS nonces (
  nonce TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  used_at TEXT
);
`;

export function openDb(dbPath = ':memory:') {
  if (dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
  }
  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA synchronous = NORMAL');
  db.exec('PRAGMA busy_timeout = 5000');
  db.exec(SCHEMA);
  return db;
}

function cleanSingleLine(value, max) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
}

function cleanMultiline(value, max) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/\r\n/g, '\n')
    .replace(/[\u0000-\u0009\u000b\u000c\u000e-\u001f\u007f]/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
    .slice(0, max);
}

function cleanUrl(value) {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  if (!trimmed) return '';
  try {
    const url = new URL(trimmed);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : '';
  } catch {
    return '';
  }
}

function cleanStringArray(value, { limit, maxLength }) {
  if (!Array.isArray(value)) return [];
  const out = [];
  const seen = new Set();
  for (const item of value) {
    const text = cleanSingleLine(item, maxLength);
    if (!text || seen.has(text)) continue;
    seen.add(text);
    out.push(text);
    if (out.length >= limit) break;
  }
  return out;
}

function cleanLinks(value, limit) {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const item of value) {
    if (!item || typeof item !== 'object') continue;
    const url = cleanUrl(item.url);
    if (!url) continue;
    out.push({ label: cleanSingleLine(item.label, 80) || new URL(url).hostname, url });
    if (out.length >= limit) break;
  }
  return out;
}

function entryFields(site) {
  const profile = site.profile || {};
  const host = new URL(site.siteUrl).hostname;
  const interests = cleanStringArray(profile.interests, { limit: 50, maxLength: 80 });
  return {
    id: site.did,
    siteUrl: site.siteUrl,
    did: site.did,
    handle: cleanSingleLine(profile.handle, 100),
    displayName: cleanSingleLine(profile.displayName, 200) || cleanSingleLine(profile.handle, 100) || host,
    tagline: cleanSingleLine(profile.tagline, 400),
    bio: cleanMultiline(profile.bio, 8000),
    location: cleanSingleLine(profile.location, 200),
    avatarUrl: cleanUrl(profile.avatarUrl),
    bannerUrl: cleanUrl(profile.bannerUrl),
    interests,
    interestsText: interests.join(' '),
    links: cleanLinks(profile.customLinks, 50),
    publicKeyPem: site.publicKeyPem,
    profileUpdatedAt: cleanSingleLine(profile.updatedAt, 100) || site.fetchedAt
  };
}

/** Inserts or refreshes the indexed copy of a verified site. */
export function upsertEntry(db, site, now = new Date().toISOString()) {
  const fields = entryFields(site);
  db.exec('BEGIN');
  try {
    const byDid = db.prepare('SELECT rowid FROM entries WHERE did = ?').get(fields.did);
    const bySite = db.prepare('SELECT rowid FROM entries WHERE site_url = ?').get(fields.siteUrl);
    if (bySite && (!byDid || Number(bySite.rowid) !== Number(byDid.rowid))) {
      db.prepare('DELETE FROM entries WHERE rowid = ?').run(bySite.rowid);
    }
    if (byDid) {
      db.prepare(
        `UPDATE entries SET
          site_url = ?, handle = ?, display_name = ?, tagline = ?, bio = ?, location = ?,
          avatar_url = ?, banner_url = ?, interests_json = ?, interests_text = ?, links_json = ?,
          public_key_pem = ?, profile_updated_at = ?, verified_at = ?, last_checked_at = ?,
          fail_count = 0, last_error = NULL,
          status = CASE WHEN status = 'blocked' THEN 'blocked' ELSE 'active' END,
          updated_at = ?
        WHERE rowid = ?`
      ).run(
        fields.siteUrl,
        fields.handle,
        fields.displayName,
        fields.tagline,
        fields.bio,
        fields.location,
        fields.avatarUrl,
        fields.bannerUrl,
        JSON.stringify(fields.interests),
        fields.interestsText,
        JSON.stringify(fields.links),
        fields.publicKeyPem,
        fields.profileUpdatedAt,
        now,
        now,
        now,
        byDid.rowid
      );
      db.exec('COMMIT');
      return { inserted: false };
    }
    db.prepare(
      `INSERT INTO entries (
        id, site_url, did, handle, display_name, tagline, bio, location, avatar_url, banner_url,
        interests_json, interests_text, links_json, public_key_pem, profile_updated_at,
        verified_at, last_checked_at, fail_count, last_error, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, 'active', ?, ?)`
    ).run(
      fields.id,
      fields.siteUrl,
      fields.did,
      fields.handle,
      fields.displayName,
      fields.tagline,
      fields.bio,
      fields.location,
      fields.avatarUrl,
      fields.bannerUrl,
      JSON.stringify(fields.interests),
      fields.interestsText,
      JSON.stringify(fields.links),
      fields.publicKeyPem,
      fields.profileUpdatedAt,
      now,
      now,
      now,
      now
    );
    db.exec('COMMIT');
    return { inserted: true };
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

/** Records a failed crawl and hides the entry after a week of failures. */
export function recordFailure(db, row, message, now = new Date().toISOString()) {
  const error = cleanSingleLine(message, 500) || 'Unknown error';
  db.prepare(
    `UPDATE entries SET
      fail_count = fail_count + 1,
      last_checked_at = ?,
      last_error = ?,
      status = CASE
        WHEN status = 'blocked' THEN 'blocked'
        WHEN fail_count + 1 >= 7 THEN 'stale'
        ELSE status
      END
    WHERE rowid = ?`
  ).run(now, error, row.rowid);
}

function ftsQuery(rawQuery) {
  const tokens = String(rawQuery).toLowerCase().match(/[\p{L}\p{N}]+/gu) || [];
  return tokens.slice(0, 8).map((token) => `${token}*`).join(' ');
}

function searchLike(db, q, limit, offset) {
  const like = `%${q.replace(/[\\%_]/g, (m) => `\\${m}`)}%`;
  const where = `status = 'active' AND (
    display_name LIKE ? ESCAPE '\\' OR handle LIKE ? ESCAPE '\\' OR tagline LIKE ? ESCAPE '\\'
    OR bio LIKE ? ESCAPE '\\' OR location LIKE ? ESCAPE '\\' OR interests_text LIKE ? ESCAPE '\\'
  )`;
  const args = [like, like, like, like, like, like];
  const total = db.prepare(`SELECT COUNT(*) AS n FROM entries WHERE ${where}`).get(...args).n;
  const rows = db
    .prepare(`SELECT * FROM entries WHERE ${where} ORDER BY display_name COLLATE NOCASE LIMIT ? OFFSET ?`)
    .all(...args, limit, offset);
  return { total: Number(total), entries: rows };
}

/** Public search over active entries; uses FTS5 with a LIKE fallback. */
export function listEntries(db, { q = '', limit = 24, offset = 0 } = {}) {
  const safeLimit = Math.min(Math.max(Number(limit) || 24, 1), 100);
  const safeOffset = Math.max(Number(offset) || 0, 0);
  const query = String(q || '').trim();

  if (!query) {
    const total = db.prepare("SELECT COUNT(*) AS n FROM entries WHERE status = 'active'").get().n;
    const rows = db
      .prepare("SELECT * FROM entries WHERE status = 'active' ORDER BY display_name COLLATE NOCASE LIMIT ? OFFSET ?")
      .all(safeLimit, safeOffset);
    return { total: Number(total), entries: rows };
  }

  const match = ftsQuery(query);
  if (!match) return { total: 0, entries: [] };

  try {
    const total = db
      .prepare(
        `SELECT COUNT(*) AS n FROM entries e
         JOIN entries_fts f ON f.rowid = e.rowid
         WHERE entries_fts MATCH ? AND e.status = 'active'`
      )
      .get(match).n;
    const rows = db
      .prepare(
        `SELECT e.* FROM entries e
         JOIN entries_fts f ON f.rowid = e.rowid
         WHERE entries_fts MATCH ? AND e.status = 'active'
         ORDER BY bm25(entries_fts), e.display_name COLLATE NOCASE
         LIMIT ? OFFSET ?`
      )
      .all(match, safeLimit, safeOffset);
    return { total: Number(total), entries: rows };
  } catch {
    return searchLike(db, query, safeLimit, safeOffset);
  }
}

export function getEntryByDid(db, did) {
  return db.prepare('SELECT * FROM entries WHERE did = ?').get(did);
}

export function getEntryBySiteUrl(db, siteUrl) {
  return db.prepare('SELECT * FROM entries WHERE site_url = ?').get(siteUrl);
}

export function deleteEntry(db, did) {
  return Number(db.prepare('DELETE FROM entries WHERE did = ?').run(did).changes) > 0;
}

export function setEntryStatus(db, did, status, now = new Date().toISOString()) {
  return Number(db.prepare('UPDATE entries SET status = ?, updated_at = ? WHERE did = ?').run(status, now, did).changes) > 0;
}

/** Rows to check on the next refresh sweep (oldest first, never blocked). */
export function listForRefresh(db, limit = 25) {
  return db
    .prepare("SELECT * FROM entries WHERE status != 'blocked' ORDER BY last_checked_at ASC LIMIT ?")
    .all(Math.min(Math.max(Number(limit) || 25, 1), 200));
}

/** Every crawlable row, for a full cron sweep. */
export function listAllForRefresh(db) {
  return db
    .prepare("SELECT * FROM entries WHERE status != 'blocked' ORDER BY last_checked_at ASC")
    .all();
}

export function createNonce(db, now = new Date().toISOString()) {
  const nonce = crypto.randomUUID().replace(/-/g, '');
  db.prepare('DELETE FROM nonces WHERE created_at < ?').run(new Date(Date.now() - 60 * 60 * 1000).toISOString());
  db.prepare('INSERT INTO nonces (nonce, created_at) VALUES (?, ?)').run(nonce, now);
  return nonce;
}

/** Atomically consumes a nonce if it exists, is unused, and is < 15 minutes old. */
export function consumeNonce(db, nonce, now = new Date().toISOString()) {
  if (typeof nonce !== 'string' || !nonce) return false;
  const row = db.prepare('SELECT created_at, used_at FROM nonces WHERE nonce = ?').get(nonce);
  if (!row || row.used_at) return false;
  if (Date.parse(now) - Date.parse(row.created_at) > 15 * 60 * 1000) return false;
  const result = db.prepare('UPDATE nonces SET used_at = ? WHERE nonce = ? AND used_at IS NULL').run(now, nonce);
  return Number(result.changes) === 1;
}

function parseJsonArray(value) {
  try {
    const parsed = JSON.parse(value || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/** The subset safe to expose on the public API and page. */
export function toPublicEntry(row) {
  return {
    id: row.did,
    siteUrl: row.site_url,
    did: row.did,
    handle: row.handle,
    displayName: row.display_name,
    tagline: row.tagline,
    bio: row.bio,
    location: row.location,
    avatarUrl: row.avatar_url,
    bannerUrl: row.banner_url,
    interests: parseJsonArray(row.interests_json),
    links: parseJsonArray(row.links_json),
    profileUpdatedAt: row.profile_updated_at,
    verifiedAt: row.verified_at,
    updatedAt: row.updated_at
  };
}

export function toAdminEntry(row) {
  return {
    ...toPublicEntry(row),
    status: row.status,
    failCount: Number(row.fail_count),
    lastError: row.last_error || '',
    lastCheckedAt: row.last_checked_at
  };
}
