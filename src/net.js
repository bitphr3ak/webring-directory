import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { AppError } from './errors.js';

const DEFAULT_USER_AGENT = 'WebringDirectory/0.1 (+https://github.com/bitphr3ak/webring-studio)';

function ipv4ToBytes(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return null;
  if (parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return parts;
}

function ipv6ToBytes(ip) {
  let address = String(ip);
  const zone = address.indexOf('%');
  if (zone !== -1) address = address.slice(0, zone);

  if (address.includes('.')) {
    const lastColon = address.lastIndexOf(':');
    const v4 = ipv4ToBytes(address.slice(lastColon + 1));
    if (!v4) return null;
    address = `${address.slice(0, lastColon + 1)}${((v4[0] << 8) | v4[1]).toString(16)}:${((v4[2] << 8) | v4[3]).toString(16)}`;
  }

  const halves = address.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0) return null;
  if (halves.length === 1 && missing !== 0) return null;
  const groups = halves.length === 2 ? [...head, ...Array(missing).fill('0'), ...tail] : head;
  if (groups.length !== 8) return null;

  const bytes = [];
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    const value = parseInt(group, 16);
    bytes.push((value >> 8) & 0xff, value & 0xff);
  }
  return bytes;
}

function isPublicV4(bytes) {
  const [a, b, c] = bytes;
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && c === 0) return false;
  if (a === 192 && b === 0 && c === 2) return false;
  if (a === 192 && b === 88 && c === 99) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  if (a >= 224) return false;
  return true;
}

function isPublicV6(bytes) {
  // ::ffff:a.b.c.d (IPv4-mapped) and ::a.b.c.d (IPv4-compatible)
  if (bytes.slice(0, 10).every((v) => v === 0)) {
    if (bytes[10] === 0xff && bytes[11] === 0xff) return isPublicV4(bytes.slice(12));
    if (bytes[10] === 0 && bytes[11] === 0) return isPublicV4(bytes.slice(12));
  }
  // Only 2000::/3 is global unicast.
  if ((bytes[0] & 0xe0) !== 0x20) return false;
  // 2001:db8::/32 documentation
  if (bytes[0] === 0x20 && bytes[1] === 0x01 && bytes[2] === 0x0d && bytes[3] === 0xb8) return false;
  // 2001:2::/48 benchmarking
  if (bytes[0] === 0x20 && bytes[1] === 0x01 && bytes[2] === 0x00 && bytes[3] === 0x02) return false;
  // 2001:10::/28 (ORCHID) and 2001:20::/28 (ORCHIDv2)
  if (bytes[0] === 0x20 && bytes[1] === 0x01 && bytes[2] === 0x00) {
    const highNibble = bytes[3] & 0xf0;
    if (highNibble === 0x10 || highNibble === 0x20) return false;
  }
  // 2001::/32 Teredo
  if (bytes[0] === 0x20 && bytes[1] === 0x01 && bytes[2] === 0x00 && bytes[3] === 0x00) return false;
  // 2002::/16 6to4
  if (bytes[0] === 0x20 && bytes[1] === 0x02) return false;
  // 3fff::/20 documentation
  if (bytes[0] === 0x3f && (bytes[1] & 0xf0) === 0xf0) return false;
  return true;
}

/** True only for globally routable unicast addresses. */
export function isPublicAddress(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const bytes = ipv4ToBytes(address);
    return bytes ? isPublicV4(bytes) : false;
  }
  if (family === 6) {
    const bytes = ipv6ToBytes(address);
    return bytes ? isPublicV6(bytes) : false;
  }
  return false;
}

function validateUrl(url, { allowInsecure, allowPrivate }) {
  if (url.protocol !== 'https:' && !(allowInsecure && url.protocol === 'http:')) {
    throw new AppError(400, 'insecure_url', 'Only https:// URLs are allowed.');
  }
  if (url.username || url.password) {
    throw new AppError(400, 'unsafe_url', 'URLs with credentials are not allowed.');
  }
  if (!url.hostname) {
    throw new AppError(400, 'invalid_url', 'The URL has no hostname.');
  }
  if (!allowPrivate && net.isIP(url.hostname) && !isPublicAddress(url.hostname)) {
    throw new AppError(400, 'unsafe_host', 'Refusing to connect to a private or reserved address.');
  }
}

function makeLookup(allowPrivate) {
  return (hostname, options, callback) => {
    dns
      .lookup(hostname, { all: true, verbatim: true })
      .then((addresses) => {
        if (!addresses.length) {
          return callback(new AppError(502, 'dns_failed', 'The hostname did not resolve.'));
        }
        if (!allowPrivate) {
          for (const entry of addresses) {
            if (!isPublicAddress(entry.address)) {
              return callback(
                new AppError(400, 'unsafe_host', `Refusing to connect to non-public address ${entry.address}.`)
              );
            }
          }
        }
        if (options && options.all) return callback(null, addresses);
        const first = addresses[0];
        callback(null, first.address, first.family);
      })
      .catch((err) => {
        callback(err instanceof AppError ? err : new AppError(502, 'dns_failed', `DNS lookup failed: ${err.message}`));
      });
  };
}

function readBody(res, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    res.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        res.destroy();
        reject(new AppError(502, 'response_too_large', 'The remote document is too large.'));
        return;
      }
      chunks.push(chunk);
    });
    res.on('end', () => resolve(Buffer.concat(chunks)));
    res.on('error', reject);
    res.on('aborted', () => reject(new AppError(502, 'fetch_aborted', 'The remote server closed the connection.')));
  });
}

function requestOnce(url, { timeoutMs, maxBytes, allowPrivate, userAgent }) {
  return new Promise((resolve, reject) => {
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.get(
      url,
      {
        headers: {
          accept: 'application/json',
          'accept-encoding': 'identity',
          'user-agent': userAgent
        },
        lookup: makeLookup(allowPrivate)
      },
      (res) => {
        const status = res.statusCode || 0;
        if (status >= 300 && status < 400) {
          const location = res.headers.location;
          res.resume();
          if (!location) return reject(new AppError(502, 'bad_redirect', 'The remote server sent an empty redirect.'));
          return resolve({ status, redirect: location });
        }
        readBody(res, maxBytes).then(
          (buffer) => {
            if (status < 200 || status >= 300) {
              const isMissing = status === 404 || status === 410;
              return reject(
                new AppError(
                  isMissing ? 404 : 502,
                  isMissing ? 'not_found' : 'fetch_failed',
                  `The remote site returned HTTP ${status} for ${url.href}.`
                )
              );
            }
            let json;
            try {
              json = JSON.parse(buffer.toString('utf8').replace(/^\uFEFF/, ''));
            } catch {
              const type = res.headers['content-type'] || 'an unknown content type';
              return reject(
                new AppError(502, 'invalid_json', `${url.href} did not return JSON (got ${type}).`)
              );
            }
            resolve({ status, json, headers: res.headers });
          },
          reject
        );
      }
    );

    req.setTimeout(timeoutMs, () => {
      req.destroy(new AppError(504, 'fetch_timeout', 'The remote site took too long to respond.'));
    });
    const hardTimer = setTimeout(() => {
      req.destroy(new AppError(504, 'fetch_timeout', 'The remote site took too long to respond.'));
    }, timeoutMs);
    req.on('close', () => clearTimeout(hardTimer));
    req.on('error', (err) => {
      clearTimeout(hardTimer);
      reject(err instanceof AppError ? err : new AppError(502, 'fetch_failed', `Could not fetch the remote site: ${err.message}`));
    });
  });
}

/**
 * Fetches and parses JSON with a public-address guard, redirect re-validation,
 * a hard timeout and a response-size cap.
 */
export async function safeGetJson(
  urlString,
  {
    timeoutMs = 8000,
    maxBytes = 2 * 1024 * 1024,
    maxRedirects = 3,
    allowInsecure = false,
    allowPrivate = false,
    userAgent = DEFAULT_USER_AGENT
  } = {}
) {
  let url;
  try {
    url = new URL(urlString);
  } catch {
    throw new AppError(400, 'invalid_url', 'The URL is not valid.');
  }

  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    validateUrl(url, { allowInsecure, allowPrivate });
    const result = await requestOnce(url, { timeoutMs, maxBytes, allowPrivate, userAgent });
    if (result.redirect) {
      if (hop === maxRedirects) {
        throw new AppError(502, 'too_many_redirects', 'The remote site redirected too many times.');
      }
      try {
        url = new URL(result.redirect, url);
      } catch {
        throw new AppError(502, 'bad_redirect', 'The remote site sent an invalid redirect.');
      }
      continue;
    }
    return { url: url.href, status: result.status, headers: result.headers, json: result.json };
  }
  throw new AppError(502, 'too_many_redirects', 'The remote site redirected too many times.');
}
