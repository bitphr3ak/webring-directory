import { AppError } from './errors.js';
import { safeGetJson } from './net.js';
import {
  normalizeSiteUrl,
  siteUrlToDidWeb,
  verifyDocumentSignature
} from './verify.js';

const MAX_JSON_BYTES = 2 * 1024 * 1024;

function fail(code, message, status = 422) {
  return new AppError(status, code, message);
}

async function fetchJson(url, options) {
  try {
    return await safeGetJson(url, options);
  } catch (err) {
    if (err instanceof AppError && err.status === 404) {
      throw fail('not_found', `No document was found at ${url}.`, 422);
    }
    throw err;
  }
}

/**
 * Webring Studio writes its manifest endpoints as site-root-relative paths
 * (`/.well-known/did.json`, `/api/profile.json`). For a site published under a
 * subpath such as https://example.com/social, those must resolve under
 * https://example.com/social, not at the origin root. They also must not be
 * allowed to point off-site.
 */
function resolveEndpoint(siteUrl, endpoint, fallback) {
  const raw = typeof endpoint === 'string' && endpoint.trim() ? endpoint.trim() : fallback;
  let resolved;
  try {
    if (/^https?:\/\//i.test(raw)) {
      resolved = new URL(raw);
    } else if (raw.startsWith('/')) {
      resolved = new URL(`${siteUrl}${raw}`);
    } else {
      resolved = new URL(raw, `${siteUrl}/`);
    }
  } catch {
    throw fail('bad_endpoint', 'The manifest contains an invalid endpoint URL.');
  }

  const site = new URL(siteUrl);
  const sitePath = site.pathname.replace(/\/+$/, '');
  if (resolved.origin !== site.origin) {
    throw fail('endpoint_offsite', 'The manifest points to a different origin.');
  }
  if (sitePath && resolved.pathname !== sitePath && !resolved.pathname.startsWith(`${sitePath}/`)) {
    throw fail('endpoint_offsite', 'The manifest endpoint is outside the site.');
  }
  return resolved.href;
}

/**
 * Fetches a site's manifest, did:web document and signed profile, then verifies:
 *
 *   1. the submitted URL matches `manifest.siteUrl`;
 *   2. `manifest.did` is the did:web for that URL;
 *   3. `/.well-known/did.json` has the same id and a PEM Ed25519 key;
 *   4. `profile.json` names the same did and site, and its Ed25519 proof verifies.
 *
 * The profile's signature is what proves the submitter controls the site's key.
 */
export async function verifySite(rawSiteUrl, options = {}) {
  const { allowInsecure = false, allowPrivate = false, timeoutMs = 8000 } = options;
  const siteUrl = normalizeSiteUrl(rawSiteUrl);
  if (!siteUrl) {
    throw fail('invalid_site_url', 'Enter a valid http(s) site URL.', 400);
  }
  if (!allowInsecure && !siteUrl.startsWith('https://')) {
    throw fail('insecure_url', 'Only https:// sites can be listed.', 400);
  }

  const site = new URL(siteUrl);
  const base = `${siteUrl}/`;
  const fetchOptions = {
    timeoutMs,
    maxBytes: MAX_JSON_BYTES,
    allowInsecure,
    allowPrivate
  };

  const manifestRes = await fetchJson(new URL('api/manifest.json', base).href, fetchOptions);
  const manifest = manifestRes.json;
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw fail('invalid_manifest', 'The site did not return a Webring Studio manifest.');
  }

  if (normalizeSiteUrl(manifest.siteUrl) !== siteUrl) {
    throw fail(
      'manifest_site_mismatch',
      'The manifest does not name the site URL that was submitted.'
    );
  }

  const did = siteUrlToDidWeb(siteUrl);
  if (!did || manifest.did !== did) {
    throw fail('manifest_did_mismatch', 'The manifest does not use the did:web for this site URL.');
  }

  const endpoints = manifest.endpoints && typeof manifest.endpoints === 'object' ? manifest.endpoints : {};
  const didUrl = resolveEndpoint(siteUrl, endpoints.did, '/.well-known/did.json');
  let didRes;
  try {
    didRes = await fetchJson(didUrl, fetchOptions);
  } catch (err) {
    const hasPath = site.pathname && site.pathname !== '/';
    if (err instanceof AppError && err.code === 'not_found' && hasPath) {
      didRes = await fetchJson(resolveEndpoint(siteUrl, 'did.json', 'did.json'), fetchOptions);
    } else {
      throw err;
    }
  }

  const didDocument = didRes.json;
  if (!didDocument || typeof didDocument !== 'object' || didDocument.id !== did) {
    throw fail('did_document_mismatch', 'The did:web document does not match this site.');
  }

  const methods = Array.isArray(didDocument.verificationMethod) ? didDocument.verificationMethod : [];
  const method = methods.find((entry) => entry && entry.id === `${did}#key-1`) || methods.find((entry) => entry && entry.publicKeyPem);
  const publicKeyPem = method && typeof method.publicKeyPem === 'string' ? method.publicKeyPem : '';
  if (!publicKeyPem.includes('BEGIN PUBLIC KEY')) {
    throw fail('missing_public_key', 'The site did not publish a PEM Ed25519 public key.');
  }

  if (manifest.proof && !verifyDocumentSignature(manifest, publicKeyPem)) {
    throw fail('manifest_signature_invalid', 'The manifest signature did not verify.');
  }

  const profileUrl = resolveEndpoint(siteUrl, endpoints.profile, '/api/profile.json');
  const profileRes = await fetchJson(profileUrl, fetchOptions);
  const profile = profileRes.json;
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)) {
    throw fail('invalid_profile', 'The site did not return a valid profile document.');
  }
  if (profile.did !== did) {
    throw fail('profile_did_mismatch', 'The profile does not use the did:web for this site URL.');
  }
  if (normalizeSiteUrl(profile.siteUrl) !== siteUrl) {
    throw fail('profile_site_mismatch', 'The profile does not name the site URL that was submitted.');
  }
  if (!verifyDocumentSignature(profile, publicKeyPem)) {
    throw fail(
      'signature_invalid',
      "The profile signature did not verify against the site's published did:web key."
    );
  }

  return {
    siteUrl,
    did,
    manifest,
    profile,
    publicKeyPem,
    fetchedAt: new Date().toISOString()
  };
}
