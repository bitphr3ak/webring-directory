import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { generateKeyPair, verifyPayloadSignature } from '../src/verify.js';

const execFileAsync = promisify(execFile);
const REPO_ROOT = path.resolve(import.meta.dirname, '..');

async function writeKey(t) {
  const keys = generateKeyPair();
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sign-request-'));
  const keyPath = path.join(dir, 'key.pem');
  await fs.writeFile(keyPath, keys.privateKeyPem, { mode: 0o600 });
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  return { keys, keyPath };
}

function runSignRequest(args) {
  return execFileAsync(process.execPath, ['scripts/sign-request.js', ...args], {
    cwd: REPO_ROOT
  });
}

test('sign-request --link prints a removal page link with a verifiable request', async (t) => {
  const { keys, keyPath } = await writeKey(t);

  const { stdout } = await runSignRequest([
    '--site-url', 'https://alice.example',
    '--nonce', 'test-nonce',
    '--dir', 'https://directory.example',
    '--key', keyPath,
    '--link'
  ]);

  const url = new URL(stdout.trim());
  assert.equal(url.origin, 'https://directory.example');
  assert.equal(url.pathname, '/remove');

  const encoded = new URLSearchParams(url.hash.slice(1)).get('request');
  assert.ok(encoded);
  const body = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  assert.equal(body.siteUrl, 'https://alice.example');
  assert.equal(body.did, 'did:web:alice.example');
  assert.equal(body.nonce, 'test-nonce');
  assert.equal(typeof body.createdAt, 'string');
  assert.equal(typeof body.signature, 'string');

  const payload = {
    action: 'remove',
    siteUrl: body.siteUrl,
    did: body.did,
    nonce: body.nonce,
    createdAt: body.createdAt
  };
  assert.ok(verifyPayloadSignature(payload, body.signature, keys.publicKeyPem));
});

test('sign-request --link requires --dir', async (t) => {
  const { keyPath } = await writeKey(t);

  await assert.rejects(
    runSignRequest([
      '--site-url', 'https://alice.example',
      '--nonce', 'test-nonce',
      '--key', keyPath,
      '--link'
    ]),
    (err) => {
      assert.equal(err.code, 1);
      assert.match(err.stderr, /--link needs --dir/);
      return true;
    }
  );
});
