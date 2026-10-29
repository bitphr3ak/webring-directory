import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalizeJson,
  generateKeyPair,
  normalizeSiteUrl,
  signPayload,
  siteUrlToDidWeb,
  verifyDocumentSignature
} from '../src/verify.js';
import { isPublicAddress } from '../src/net.js';

test('normalizeSiteUrl adds https and removes the trailing slash', () => {
  assert.equal(normalizeSiteUrl('example.com'), 'https://example.com');
  assert.equal(normalizeSiteUrl('https://example.com/'), 'https://example.com');
  assert.equal(normalizeSiteUrl('  https://example.com/sub/  '), 'https://example.com/sub');
  assert.equal(normalizeSiteUrl(''), '');
  assert.equal(normalizeSiteUrl('ftp://example.com'), '');
});

test('siteUrlToDidWeb matches Studio for hosts, ports and paths', () => {
  assert.equal(siteUrlToDidWeb('https://example.com'), 'did:web:example.com');
  assert.equal(siteUrlToDidWeb('https://example.com/'), 'did:web:example.com');
  assert.equal(siteUrlToDidWeb('https://example.com/people/alice'), 'did:web:example.com:people:alice');
  assert.equal(siteUrlToDidWeb('http://127.0.0.1:8080'), 'did:web:127.0.0.1%3A8080');
});

test('canonicalization sorts object keys, drops proof, and leaves arrays alone', () => {
  const input = {
    b: 1,
    a: { d: 4, c: 3, proof: { ignored: true } },
    proof: { signatureValue: 'nope' },
    arr: [{ b: 2, a: 1 }]
  };
  assert.equal(canonicalizeJson(input), '{"a":{"c":3,"d":4},"arr":[{"b":2,"a":1}],"b":1}');
});

test('Ed25519 document signatures verify and tampering fails', () => {
  const { publicKeyPem, privateKeyPem } = generateKeyPair();
  const doc = {
    schemaVersion: '1.0.0',
    did: 'did:web:example.com',
    siteUrl: 'https://example.com',
    displayName: 'Alice',
    updatedAt: '2026-01-01T00:00:00.000Z'
  };
  const signed = {
    ...doc,
    proof: {
      type: 'Ed25519Signature2020',
      created: '2026-01-01T00:00:00.000Z',
      verificationMethod: 'did:web:example.com#key-1',
      signatureValue: signPayload(doc, privateKeyPem)
    }
  };
  assert.equal(verifyDocumentSignature(signed, publicKeyPem), true);
  assert.equal(verifyDocumentSignature({ ...signed, displayName: 'Mallory' }, publicKeyPem), false);
  assert.equal(verifyDocumentSignature({ ...signed, proof: undefined }, publicKeyPem), false);

  const other = generateKeyPair();
  assert.equal(verifyDocumentSignature(signed, other.publicKeyPem), false);
});

test('private, loopback and reserved addresses are rejected', () => {
  const blocked = [
    '0.0.0.0',
    '10.0.0.1',
    '100.64.0.1',
    '127.0.0.1',
    '169.254.1.1',
    '172.16.0.1',
    '192.168.1.1',
    '198.18.0.1',
    '224.0.0.1',
    '255.255.255.255',
    '::',
    '::1',
    '::ffff:127.0.0.1',
    'fe80::1',
    'fc00::1',
    'ff02::1',
    '2001:db8::1',
    '2001::1',
    '2002::1',
    '64:ff9b::1'
  ];
  for (const address of blocked) assert.equal(isPublicAddress(address), false, address);

  const allowed = ['1.1.1.1', '8.8.8.8', '9.9.9.9', '2606:4700:4700::1111', '2001:4860:4860::8888'];
  for (const address of allowed) assert.equal(isPublicAddress(address), true, address);
});
