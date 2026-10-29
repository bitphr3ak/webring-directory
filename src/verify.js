import crypto from 'node:crypto';

/**
 * Interoperability note
 * ---------------------
 * Webring Studio signs JSON documents with Ed25519 over a bespoke canonical form:
 * object keys are sorted recursively, arrays are left in the order they appear, and
 * any `proof` property is dropped at every object level. That is *not* RFC 8785/JCS,
 * so this module reproduces the exact behaviour rather than approximating it.
 */

export class VerifyError extends Error {
  constructor(message, code = 'verification_failed') {
    super(message);
    this.name = 'VerifyError';
    this.code = code;
  }
}

/** Normalises a site URL the same way Studio does (https by default, no trailing slash). */
export function normalizeSiteUrl(rawUrl) {
  const trimmed = String(rawUrl ?? '').trim();
  if (!trimmed) return '';
  const hasExplicitScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed);
  if (hasExplicitScheme && !/^https?:\/\//i.test(trimmed)) return '';
  const withProto = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let url;
  try {
    url = new URL(withProto);
  } catch {
    return '';
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return '';
  if (url.username || url.password) return '';
  if (url.search || url.hash) return '';
  const href = url.href;
  return href.endsWith('/') ? href.slice(0, -1) : href;
}

/** Converts an HTTP(S) site URL into a did:web identifier, matching Studio. */
export function siteUrlToDidWeb(siteUrl) {
  const normalized = normalizeSiteUrl(siteUrl);
  if (!normalized) return '';
  try {
    const parsed = new URL(normalized);
    const host = parsed.port ? `${parsed.hostname}%3A${parsed.port}` : parsed.hostname;
    const segments = parsed.pathname
      .split('/')
      .filter(Boolean)
      .map((segment) => encodeURIComponent(segment));
    return segments.length > 0 ? `did:web:${host}:${segments.join(':')}` : `did:web:${host}`;
  } catch {
    return '';
  }
}

/**
 * Mirrors Webring Studio's `canonicalizeJson`. Only call this with an object.
 * Arrays (including objects inside them) keep their original element/key order.
 */
export function canonicalizeJson(obj) {
  const clone = {};
  for (const key of Object.keys(obj).sort()) {
    if (key === 'proof') continue;
    const value = obj[key];
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      clone[key] = JSON.parse(canonicalizeJson(value));
    } else {
      clone[key] = value;
    }
  }
  return JSON.stringify(clone);
}

/** Signs a payload (without a proof field) and returns a base64url Ed25519 signature. */
export function signPayload(payload, privateKeyPem) {
  const canonical = canonicalizeJson(payload);
  return crypto.sign(null, Buffer.from(canonical, 'utf8'), privateKeyPem).toString('base64url');
}

/** Verifies a base64url Ed25519 signature over a payload. */
export function verifyPayloadSignature(payload, signatureValue, publicKeyPem) {
  try {
    const signature = Buffer.from(String(signatureValue), 'base64url');
    if (!signature.length) return false;
    return crypto.verify(null, Buffer.from(canonicalizeJson(payload), 'utf8'), publicKeyPem, signature);
  } catch {
    return false;
  }
}

/** Verifies the `proof` on a fetched Webring Studio document. */
export function verifyDocumentSignature(doc, publicKeyPem) {
  if (!doc || typeof doc !== 'object') return false;
  const proof = doc.proof;
  if (!proof || typeof proof.signatureValue !== 'string') return false;
  return verifyPayloadSignature(doc, proof.signatureValue, publicKeyPem);
}

/** Short, stable fingerprint of a public key (same scheme as Studio). */
export function publicKeyFingerprint(publicKeyPem) {
  return crypto.createHash('sha256').update(String(publicKeyPem).trim()).digest('hex').slice(0, 32);
}

/** Generates an Ed25519 keypair in PEM form. Used by tests and the CLI helper. */
export function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}
