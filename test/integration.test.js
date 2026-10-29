import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { generateKeyPair, signPayload, siteUrlToDidWeb } from '../src/verify.js';
import { createDirectoryServer } from '../src/server.js';

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve(`http://127.0.0.1:${port}`);
    });
  });
}

function closeNodeServer(server) {
  return new Promise((resolve) => {
    server.close(() => resolve());
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
  });
}

async function startFixture({ badSignature = false, sitePath = '' } = {}) {
  const keys = generateKeyPair();
  const wrongKeys = badSignature ? generateKeyPair() : keys;
  let siteUrl = '';
  let did = '';

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const json = (status, body) => {
      const data = JSON.stringify(body);
      res.writeHead(status, {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(data)
      });
      res.end(data);
    };

    if (sitePath && url.pathname !== sitePath && !url.pathname.startsWith(`${sitePath}/`)) {
      return json(404, { error: 'not_found' });
    }
    const route = sitePath ? url.pathname.slice(sitePath.length) || '/' : url.pathname;

    if (route === '/api/manifest.json') {
      return json(200, {
        schemaVersion: '1.0.0',
        siteUrl,
        did,
        updatedAt: '2026-01-01T00:00:00.000Z',
        endpoints: {
          did: '/.well-known/did.json',
          profile: '/api/profile.json',
          albums: '/api/albums.json',
          items: '/api/items.json',
          connections: '/api/connections.json'
        },
        stats: { albumCount: 0, photoCount: 0, itemCount: 0, friendCount: 0, webringCount: 0 }
      });
    }

    if (route === '/.well-known/did.json') {
      return json(200, {
        '@context': [
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/suites/ed25519-2020/v1'
        ],
        id: did,
        verificationMethod: [
          {
            id: `${did}#key-1`,
            type: 'Ed25519VerificationKey2020',
            controller: did,
            publicKeyPem: keys.publicKeyPem
          }
        ],
        service: []
      });
    }

    if (route === '/api/profile.json') {
      const profile = {
        schemaVersion: '1.0.0',
        did,
        siteUrl,
        handle: '@alice',
        displayName: 'Alice Example',
        tagline: 'Tiny web enthusiast',
        bio: 'I make small sites.\nA second line.',
        location: 'Halifax, NS',
        avatarUrl: '',
        bannerUrl: '',
        interests: ['indie web', 'photography'],
        customLinks: [{ label: 'Blog', url: 'https://example.com/blog' }],
        updatedAt: '2026-01-01T00:00:00.000Z'
      };
      return json(200, {
        ...profile,
        proof: {
          type: 'Ed25519Signature2020',
          created: '2026-01-01T00:00:00.000Z',
          verificationMethod: `${did}#key-1`,
          signatureValue: signPayload(profile, wrongKeys.privateKeyPem)
        }
      });
    }

    json(404, { error: 'not_found' });
  });

  const origin = await listen(server);
  siteUrl = `${origin}${sitePath}`;
  did = siteUrlToDidWeb(siteUrl);
  return { server, siteUrl, did, privateKeyPem: keys.privateKeyPem };
}

async function startDirectory() {
  const app = createDirectoryServer({
    dbPath: ':memory:',
    allowInsecure: true,
    allowPrivate: true,
    adminToken: 'test-admin',
    rateLimitEnabled: false
  });
  const url = await listen(app.server);
  return { app, url };
}

async function postJson(url, body) {
  return fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify(body)
  });
}

test('adds a verified site, searches it, and removes it with a signed request', async (t) => {
  const fixture = await startFixture();
  const directory = await startDirectory();
  t.after(async () => {
    await new Promise((resolve) => directory.app.close(resolve));
    await closeNodeServer(fixture.server);
  });

  const addRes = await postJson(`${directory.url}/api/entries`, { siteUrl: fixture.siteUrl });
  assert.equal(addRes.status, 201);
  const added = await addRes.json();
  assert.equal(added.entry.displayName, 'Alice Example');
  assert.equal(added.entry.handle, '@alice');
  assert.equal(added.entry.siteUrl, fixture.siteUrl);
  assert.equal(added.entry.did, fixture.did);
  assert.deepEqual(added.entry.interests, ['indie web', 'photography']);
  assert.deepEqual(added.entry.links, [{ label: 'Blog', url: 'https://example.com/blog' }]);
  assert.equal(added.entry.publicKeyPem, undefined);
  assert.equal(added.entry.lastError, undefined);

  const again = await postJson(`${directory.url}/api/entries`, { siteUrl: fixture.siteUrl });
  assert.equal(again.status, 200);

  const hit = await (await fetch(`${directory.url}/api/entries?q=photography`)).json();
  assert.equal(hit.total, 1);
  assert.equal(hit.entries[0].displayName, 'Alice Example');

  const miss = await (await fetch(`${directory.url}/api/entries?q=zzzznope`)).json();
  assert.equal(miss.total, 0);

  const nonceData = await (await fetch(`${directory.url}/api/nonce`)).json();
  const createdAt = new Date().toISOString();
  const payload = {
    action: 'remove',
    siteUrl: fixture.siteUrl,
    did: fixture.did,
    nonce: nonceData.nonce,
    createdAt
  };
  const signature = signPayload(payload, fixture.privateKeyPem);

  const removeRes = await postJson(
    `${directory.url}/api/entries/${encodeURIComponent(fixture.did)}/remove`,
    {
      siteUrl: fixture.siteUrl,
      did: fixture.did,
      nonce: nonceData.nonce,
      createdAt,
      signature
    }
  );
  assert.equal(removeRes.status, 204);

  const after = await (await fetch(`${directory.url}/api/entries`)).json();
  assert.equal(after.total, 0);
});

test('resolves manifest endpoints under a subpath site', async (t) => {
  const fixture = await startFixture({ sitePath: '/social' });
  const directory = await startDirectory();
  t.after(async () => {
    await new Promise((resolve) => directory.app.close(resolve));
    await closeNodeServer(fixture.server);
  });

  const addRes = await postJson(`${directory.url}/api/entries`, { siteUrl: fixture.siteUrl });
  assert.equal(addRes.status, 201);
  const added = await addRes.json();
  assert.equal(added.entry.siteUrl, fixture.siteUrl);
  assert.equal(added.entry.did, fixture.did);
  assert.equal(added.entry.displayName, 'Alice Example');
});

test('a profile signed by the wrong key is rejected', async (t) => {
  const fixture = await startFixture({ badSignature: true });
  const directory = await startDirectory();
  t.after(async () => {
    await new Promise((resolve) => directory.app.close(resolve));
    await closeNodeServer(fixture.server);
  });

  const response = await postJson(`${directory.url}/api/entries`, { siteUrl: fixture.siteUrl });
  assert.equal(response.status, 422);
  const data = await response.json();
  assert.equal(data.error, 'signature_invalid');

  const list = await (await fetch(`${directory.url}/api/entries`)).json();
  assert.equal(list.total, 0);
});

test('a dirty did:web or site URL mismatch is rejected', async (t) => {
  const directory = await startDirectory();
  t.after(async () => {
    await new Promise((resolve) => directory.app.close(resolve));
  });

  const response = await postJson(`${directory.url}/api/entries`, {
    siteUrl: 'https://this-domain-does-not-exist.invalid'
  });
  assert.ok([422, 502].includes(response.status));
});

test('admin can block, unblock and delete an entry', async (t) => {
  const fixture = await startFixture();
  const directory = await startDirectory();
  t.after(async () => {
    await new Promise((resolve) => directory.app.close(resolve));
    await closeNodeServer(fixture.server);
  });

  const addRes = await postJson(`${directory.url}/api/entries`, { siteUrl: fixture.siteUrl });
  assert.equal(addRes.status, 201);
  const didPath = encodeURIComponent(fixture.did);

  const unauthorized = await postJson(`${directory.url}/api/admin/entries/${didPath}/status`, {
    status: 'blocked'
  });
  assert.equal(unauthorized.status, 401);

  const blocked = await fetch(`${directory.url}/api/admin/entries/${didPath}/status`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer test-admin' },
    body: JSON.stringify({ status: 'blocked' })
  });
  assert.equal(blocked.status, 200);
  assert.equal((await blocked.json()).entry.status, 'blocked');

  const hidden = await (await fetch(`${directory.url}/api/entries`)).json();
  assert.equal(hidden.total, 0);

  const deleted = await fetch(`${directory.url}/api/admin/entries/${didPath}`, {
    method: 'DELETE',
    headers: { authorization: 'Bearer test-admin' }
  });
  assert.equal(deleted.status, 204);
});

test('serves the removal page and its script', async (t) => {
  const directory = await startDirectory();
  t.after(() => new Promise((resolve) => directory.app.close(resolve)));

  const page = await fetch(`${directory.url}/remove`);
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-type') || '', /^text\/html/);
  assert.equal(page.headers.get('cache-control'), 'no-cache');
  assert.match(page.headers.get('content-security-policy') || '', /default-src 'self'/);
  const html = await page.text();
  assert.match(html, /Remove your site/);
  assert.match(html, /\/remove\.js/);

  const alias = await fetch(`${directory.url}/remove.html`);
  assert.equal(alias.status, 200);

  const trailing = await fetch(`${directory.url}/remove/`);
  assert.equal(trailing.status, 200);

  const script = await fetch(`${directory.url}/remove.js`);
  assert.equal(script.status, 200);
  assert.match(script.headers.get('content-type') || '', /^text\/javascript/);
  const source = await script.text();
  assert.match(source, /\/api\/nonce/);
  assert.match(source, /\/remove/);
});
