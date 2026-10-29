import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  consumeNonce,
  createNonce,
  deleteEntry,
  getEntryByDid,
  listEntries,
  listForRefresh,
  openDb,
  recordFailure,
  setEntryStatus,
  toAdminEntry,
  toPublicEntry,
  upsertEntry
} from './db.js';
import { AppError, toAppError } from './errors.js';
import { verifySite } from './site.js';
import { normalizeSiteUrl, verifyPayloadSignature } from './verify.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(HERE, '..', 'public');
const MAX_BODY_BYTES = 64 * 1024;
const NONCE_TTL_MS = 15 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 10 * 60 * 1000;

const STATIC_FILES = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/index.html', ['index.html', 'text/html; charset=utf-8']],
  ['/remove', ['remove.html', 'text/html; charset=utf-8']],
  ['/remove/', ['remove.html', 'text/html; charset=utf-8']],
  ['/remove.html', ['remove.html', 'text/html; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/remove.js', ['remove.js', 'text/javascript; charset=utf-8']],
  ['/style.css', ['style.css', 'text/css; charset=utf-8']],
  ['/favicon.svg', ['favicon.svg', 'image/svg+xml']]
]);

const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "img-src 'self' https: http: data:",
  "style-src 'self'",
  "script-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'"
].join('; ');

function setCommonHeaders(res) {
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('x-frame-options', 'DENY');
}

function sendJson(res, status, body, extraHeaders = {}) {
  const payload = JSON.stringify(body);
  setCommonHeaders(res);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
    ...extraHeaders
  });
  res.end(payload);
}

function sendError(res, err) {
  const appError = toAppError(err);
  if (appError.status >= 500) console.error(`[directory] ${appError.code}: ${appError.details || appError.message}`);
  sendJson(res, appError.status, {
    error: appError.code,
    message: appError.message
  });
}

async function readJsonBody(req, maxBytes = MAX_BODY_BYTES) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw new AppError(413, 'body_too_large', 'Request body is too large.');
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new AppError(400, 'invalid_json', 'Request body must be JSON.');
  }
}

function clientIp(req, trustProxy) {
  if (trustProxy) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) {
      return forwarded.split(',')[0].trim();
    }
  }
  const address = req.socket.remoteAddress || 'unknown';
  return address.startsWith('::ffff:') ? address.slice(7) : address;
}

function createRateLimiter({ windowMs, max }) {
  const buckets = new Map();
  let lastSweep = Date.now();
  return function allow(key) {
    const now = Date.now();
    if (now - lastSweep > windowMs) {
      for (const [bucketKey, bucket] of buckets) {
        if (bucket.reset <= now) buckets.delete(bucketKey);
      }
      lastSweep = now;
    }
    const bucket = buckets.get(key);
    if (!bucket || bucket.reset <= now) {
      buckets.set(key, { count: 1, reset: now + windowMs });
      return { ok: true, retryAfter: 0 };
    }
    if (bucket.count >= max) {
      return { ok: false, retryAfter: Math.ceil((bucket.reset - now) / 1000) };
    }
    bucket.count += 1;
    return { ok: true, retryAfter: 0 };
  };
}

function adminOk(req, adminToken) {
  if (!adminToken) return false;
  const header = req.headers.authorization;
  if (typeof header !== 'string') return false;
  const match = /^Bearer (.+)$/.exec(header);
  if (!match) return false;
  const provided = Buffer.from(match[1]);
  const expected = Buffer.from(adminToken);
  if (provided.length !== expected.length) return false;
  return crypto.timingSafeEqual(provided, expected);
}

function requireAdmin(req, adminToken) {
  if (!adminToken) throw new AppError(503, 'admin_disabled', 'Admin access is not configured.');
  if (!adminOk(req, adminToken)) throw new AppError(401, 'unauthorized', 'A valid admin token is required.');
}

async function mapWithConcurrency(items, concurrency, fn) {
  const results = new Array(items.length);
  let index = 0;
  const workers = Array.from({ length: Math.min(Math.max(concurrency, 1), items.length) }, async () => {
    while (index < items.length) {
      const current = index;
      index += 1;
      try {
        results[current] = { ok: true, value: await fn(items[current]) };
      } catch (err) {
        results[current] = { ok: false, error: err };
      }
    }
  });
  await Promise.all(workers);
  return results;
}

function parseLimit(value, fallback, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(Math.max(Math.trunc(number), 1), max);
}

function decodeParam(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new AppError(400, 'invalid_path', 'Malformed URL path.');
  }
}

export function createDirectoryServer({
  dbPath = ':memory:',
  adminToken = '',
  allowInsecure = false,
  allowPrivate = false,
  trustProxy = false,
  rateLimitEnabled = true,
  writeRateLimit = { windowMs: 60 * 60 * 1000, max: 30 },
  refreshTimeoutMs = 8000
} = {}) {
  const db = openDb(dbPath);
  const writeLimiter = createRateLimiter(writeRateLimit);

  function enforceWriteLimit(req) {
    if (!rateLimitEnabled) return;
    const result = writeLimiter(clientIp(req, trustProxy));
    if (!result.ok) {
      throw new AppError(429, 'rate_limited', 'Too many requests. Try again later.', `${result.retryAfter}s`);
    }
  }

  async function serveStatic(req, res, pathname) {
    const file = STATIC_FILES.get(pathname);
    if (!file) {
      if (pathname === '/favicon.ico') {
        res.writeHead(204);
        res.end();
        return;
      }
      throw new AppError(404, 'not_found', 'Not found.');
    }
    const [name, type] = file;
    const data = await fs.readFile(path.join(PUBLIC_DIR, name));
    setCommonHeaders(res);
    const headers = {
      'content-type': type,
      'content-length': data.length,
      'cache-control': name === 'index.html' || name === 'remove.html' ? 'no-cache' : 'public, max-age=300'
    };
    if (type.startsWith('text/html')) headers['content-security-policy'] = CONTENT_SECURITY_POLICY;
    res.writeHead(200, headers);
    res.end(data);
  }

  async function handle(req, res) {
    const url = new URL(req.url || '/', 'http://localhost');
    const pathname = url.pathname;

    if (req.method === 'GET' || req.method === 'HEAD') {
      if (!pathname.startsWith('/api/')) {
        if (req.method === 'HEAD') {
          const file = STATIC_FILES.get(pathname);
          if (!file) throw new AppError(404, 'not_found', 'Not found.');
          const data = await fs.readFile(path.join(PUBLIC_DIR, file[0]));
          setCommonHeaders(res);
          const headers = { 'content-type': file[1], 'content-length': data.length, 'cache-control': 'no-cache' };
          if (file[1].startsWith('text/html')) headers['content-security-policy'] = CONTENT_SECURITY_POLICY;
          res.writeHead(200, headers);
          res.end();
          return;
        }
        return serveStatic(req, res, pathname);
      }

      if (pathname === '/api/healthz') {
        return sendJson(res, 200, { ok: true });
      }

      if (pathname === '/api/entries') {
        const result = listEntries(db, {
          q: url.searchParams.get('q') || '',
          limit: parseLimit(url.searchParams.get('limit'), 24, 100),
          offset: Math.max(Number(url.searchParams.get('offset')) || 0, 0)
        });
        return sendJson(res, 200, {
          total: result.total,
          entries: result.entries.map(toPublicEntry)
        });
      }

      const getMatch = pathname.match(/^\/api\/entries\/([^/]+)$/);
      if (getMatch) {
        const did = decodeParam(getMatch[1]);
        const row = getEntryByDid(db, did);
        if (!row || row.status !== 'active') throw new AppError(404, 'not_found', 'No such entry.');
        return sendJson(res, 200, { entry: toPublicEntry(row) });
      }

      if (pathname === '/api/nonce') {
        enforceWriteLimit(req);
        const now = new Date();
        const nonce = createNonce(db, now.toISOString());
        return sendJson(res, 200, {
          nonce,
          expiresAt: new Date(now.getTime() + NONCE_TTL_MS).toISOString()
        });
      }

      throw new AppError(404, 'not_found', 'Not found.');
    }

    if (req.method === 'POST') {
      if (pathname === '/api/entries') {
        enforceWriteLimit(req);
        const body = await readJsonBody(req);
        if (!body || typeof body.siteUrl !== 'string') {
          throw new AppError(400, 'invalid_request', 'Send JSON like {"siteUrl":"https://example.com"}.');
        }
        const site = await verifySite(body.siteUrl, { allowInsecure, allowPrivate, timeoutMs: refreshTimeoutMs });
        const { inserted } = upsertEntry(db, site);
        const row = getEntryByDid(db, site.did);
        if (row.status === 'blocked') {
          throw new AppError(403, 'entry_blocked', 'This site is blocked in the directory. Contact the operator.');
        }
        return sendJson(res, inserted ? 201 : 200, { entry: toPublicEntry(row) });
      }

      const refreshMatch = pathname.match(/^\/api\/entries\/([^/]+)\/refresh$/);
      if (refreshMatch) {
        enforceWriteLimit(req);
        const did = decodeParam(refreshMatch[1]);
        const row = getEntryByDid(db, did);
        if (!row || row.status === 'blocked') throw new AppError(404, 'not_found', 'No such entry.');
        const site = await verifySite(row.site_url, { allowInsecure, allowPrivate, timeoutMs: refreshTimeoutMs });
        if (site.did !== row.did) {
          throw new AppError(409, 'identity_changed', 'The site now publishes a different did:web identity.');
        }
        upsertEntry(db, site);
        return sendJson(res, 200, { entry: toPublicEntry(getEntryByDid(db, did)) });
      }

      const removeMatch = pathname.match(/^\/api\/entries\/([^/]+)\/remove$/);
      if (removeMatch) {
        enforceWriteLimit(req);
        const did = decodeParam(removeMatch[1]);
        const row = getEntryByDid(db, did);
        if (!row) throw new AppError(404, 'not_found', 'No such entry.');

        const body = await readJsonBody(req);
        const { siteUrl, nonce, createdAt, signature } = body || {};
        if (typeof siteUrl !== 'string' || typeof nonce !== 'string' || typeof createdAt !== 'string' || typeof signature !== 'string') {
          throw new AppError(400, 'invalid_request', 'A signed removal request needs siteUrl, nonce, createdAt and signature.');
        }
        if (body.did && body.did !== row.did) {
          throw new AppError(403, 'did_mismatch', 'The request did not name this entry.');
        }
        if (normalizeSiteUrl(siteUrl) !== row.site_url) {
          throw new AppError(403, 'site_mismatch', 'The request did not name this entry.');
        }
        const created = Date.parse(createdAt);
        if (!Number.isFinite(created) || Math.abs(Date.now() - created) > MAX_CLOCK_SKEW_MS) {
          throw new AppError(400, 'stale_request', 'The signed request is missing or too old.');
        }

        const payload = {
          action: 'remove',
          siteUrl: row.site_url,
          did: row.did,
          nonce,
          createdAt
        };
        if (!verifyPayloadSignature(payload, signature, row.public_key_pem)) {
          throw new AppError(403, 'invalid_signature', 'The removal signature did not verify for this entry.');
        }
        if (!consumeNonce(db, nonce)) {
          throw new AppError(409, 'invalid_nonce', 'The nonce is unknown, expired, or already used.');
        }
        deleteEntry(db, row.did);
        setCommonHeaders(res);
        res.writeHead(204);
        res.end();
        return;
      }

      if (pathname === '/api/admin/refresh') {
        requireAdmin(req, adminToken);
        const body = await readJsonBody(req);
        const limit = parseLimit(body && body.limit, 10, 25);
        const rows = listForRefresh(db, limit);
        const results = await mapWithConcurrency(rows, 4, async (row) => {
          const site = await verifySite(row.site_url, { allowInsecure, allowPrivate, timeoutMs: refreshTimeoutMs });
          if (site.did !== row.did) {
            throw new AppError(409, 'identity_changed', 'The site now publishes a different did:web identity.');
          }
          return site;
        });
        let updated = 0;
        let failed = 0;
        for (let i = 0; i < rows.length; i += 1) {
          const result = results[i];
          if (result.ok) {
            upsertEntry(db, result.value);
            updated += 1;
          } else {
            const message = result.error instanceof AppError ? result.error.message : String(result.error);
            recordFailure(db, rows[i], message);
            failed += 1;
          }
        }
        return sendJson(res, 200, { checked: rows.length, updated, failed });
      }

      const statusMatch = pathname.match(/^\/api\/admin\/entries\/([^/]+)\/status$/);
      if (statusMatch) {
        requireAdmin(req, adminToken);
        const did = decodeParam(statusMatch[1]);
        const body = await readJsonBody(req);
        const status = body && body.status;
        if (!['active', 'blocked', 'stale'].includes(status)) {
          throw new AppError(400, 'invalid_status', 'status must be active, blocked or stale.');
        }
        if (!setEntryStatus(db, did, status)) throw new AppError(404, 'not_found', 'No such entry.');
        return sendJson(res, 200, { entry: toAdminEntry(getEntryByDid(db, did)) });
      }

      throw new AppError(404, 'not_found', 'Not found.');
    }

    if (req.method === 'DELETE') {
      const adminMatch = pathname.match(/^\/api\/admin\/entries\/([^/]+)$/);
      if (adminMatch) {
        requireAdmin(req, adminToken);
        const did = decodeParam(adminMatch[1]);
        if (!deleteEntry(db, did)) throw new AppError(404, 'not_found', 'No such entry.');
        setCommonHeaders(res);
        res.writeHead(204);
        res.end();
        return;
      }
      throw new AppError(404, 'not_found', 'Not found.');
    }

    if (req.method === 'OPTIONS') {
      res.writeHead(204, { allow: 'GET, HEAD, POST, DELETE, OPTIONS' });
      res.end();
      return;
    }

    throw new AppError(405, 'method_not_allowed', 'Method not allowed.');
  }

  const server = http.createServer((req, res) => {
    if (req.url && !req.url.startsWith('/')) {
      sendError(res, new AppError(400, 'bad_request', 'Bad request.'));
      return;
    }
    handle(req, res).catch((err) => sendError(res, err));
  });

  server.on('clientError', (err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });

  function close(callback) {
    server.close(() => {
      try {
        db.close();
      } catch {
        // already closed
      }
      if (callback) callback();
    });
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
  }

  return { server, db, close };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  const port = Number(process.env.PORT || 8080);
  const dbPath = process.env.DATABASE_PATH || path.resolve('data', 'directory.db');
  const app = createDirectoryServer({
    dbPath,
    adminToken: process.env.ADMIN_TOKEN || '',
    allowInsecure: process.env.ALLOW_INSECURE === '1',
    allowPrivate: process.env.ALLOW_PRIVATE_HOSTS === '1',
    trustProxy: process.env.TRUST_PROXY === '1',
    rateLimitEnabled: process.env.RATE_LIMIT !== '0'
  });

  app.server.listen(port, () => {
    console.log(`webring-directory listening on http://localhost:${port}`);
    if (!process.env.ADMIN_TOKEN) console.log('admin endpoints disabled (set ADMIN_TOKEN to enable)');
  });

  const shutdown = () => {
    app.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
