#!/usr/bin/env node
import fs from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { normalizeSiteUrl, signPayload, siteUrlToDidWeb } from '../src/verify.js';

const { values } = parseArgs({
  options: {
    'site-url': { type: 'string' },
    did: { type: 'string' },
    nonce: { type: 'string' },
    key: { type: 'string' },
    created: { type: 'string' },
    dir: { type: 'string' },
    curl: { type: 'boolean' },
    link: { type: 'boolean' }
  }
});

function fail(message) {
  console.error(`sign-request: ${message}`);
  process.exit(1);
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

const siteUrl = normalizeSiteUrl(values['site-url'] || '');
if (!siteUrl) fail('--site-url is required (for example https://you.example).');

const did = values.did || siteUrlToDidWeb(siteUrl);
if (!did) fail('could not derive a did:web; pass --did explicitly.');

if (!values.key) fail('--key is required (a PKCS#8 Ed25519 private key PEM, or "-" for stdin).');
const privateKeyPem = values.key === '-' ? await readStdin() : await fs.readFile(values.key, 'utf8');
if (!privateKeyPem.includes('BEGIN PRIVATE KEY')) fail('the key file is not a PKCS#8 private key PEM.');

let nonce = values.nonce;
let directory = '';
if (values.dir) {
  directory = values.dir.replace(/\/+$/, '');
  if (directory && !/^https?:\/\//i.test(directory)) directory = `https://${directory}`;
}
if (!nonce && directory) {
  const response = await fetch(`${directory}/api/nonce`, { headers: { accept: 'application/json' } });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.nonce) fail(`could not get a nonce from ${directory} (HTTP ${response.status}).`);
  nonce = data.nonce;
}
if (!nonce) fail('--nonce is required unless --dir is given (the directory hands one out).');

const createdAt = values.created || new Date().toISOString();
const payload = { action: 'remove', siteUrl, did, nonce, createdAt };
const signature = signPayload(payload, privateKeyPem);
const body = { siteUrl, did, nonce, createdAt, signature };

if (values.curl && values.link) fail('choose one of --curl or --link.');

if (values.link) {
  if (!directory) fail('--link needs --dir so it knows which directory to link to.');
  const encoded = Buffer.from(JSON.stringify(body), 'utf8').toString('base64url');
  const url = new URL('/remove', directory);
  url.hash = `request=${encoded}`;
  console.log(url.href);
} else if (values.curl) {
  const base = directory || '<directory-url>';
  const command = [
    `curl -X POST '${base}/api/entries/${encodeURIComponent(did)}/remove'`,
    `  -H 'content-type: application/json'`,
    `  --data '${JSON.stringify(body)}'`
  ].join(' \\\n');
  console.log(command);
} else {
  console.log(JSON.stringify(body, null, 2));
}
