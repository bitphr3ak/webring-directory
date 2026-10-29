# Webring Directory

An opt-in, **verified** public index of [Webring Studio](https://github.com/bitphr3ak/webring-studio) sites.

Webring Studio deliberately has no central user search: each persona is a folder of signed
HTML/JSON on its own host. This is a small server you can run yourself that lets people
*choose* to be listed, proves each listing is controlled by the site's owner, and keeps the
index up to date from the site's own published files.

- **Add** — submit a site URL; the directory fetches and verifies it.
- **Edit** — re-submitting, or the scheduled refresh, picks up the latest signed profile.
- **Delete** — the `/remove` page, which collects a fresh Ed25519-signed request (or an admin takedown).

No accounts, cookies, or tracking. One SQLite file. Zero npm dependencies.

---

## How verification works

A Webring Studio site publishes:

| File | Purpose |
| --- | --- |
| `api/manifest.json` | Site URL, `did:web`, endpoint paths, stats |
| `/.well-known/did.json` | The owner's Ed25519 public key (`publicKeyPem`) |
| `api/profile.json` | Public profile, carrying an `Ed25519Signature2020` proof |

To list a site the directory:

1. normalises the submitted URL and fetches `api/manifest.json`;
2. checks the manifest names the same `siteUrl` and `did`;
3. fetches the `did:web` document and requires `id` to match;
4. fetches `api/profile.json` and verifies its proof against the published key;
5. stores only the public profile fields in SQLite.

The signature check is what makes the listing meaningful: a site that cannot sign with the
key published at its own domain cannot be added. The canonicalisation is the same bespoke
scheme Studio uses (recursively sorted object keys, arrays left alone, `proof` excluded), not
JCS. See `src/verify.js`.

### Opt-in caveat

Submitting a URL proves the site exists and is validly signed; it does **not** prove the
person clicking submit is the owner. The indexed fields are already public, and removal still
requires a signed request (or an admin takedown), so the practical risk is low. For a strict
owner-initiated opt-in, the natural next step is a Studio-side “Add to this directory” action
that signs a claim containing the directory URL. The API is ready for that: the same nonce +
Ed25519 pattern used for removal can authorise a claim.

## Quick start

Requires **Node 24+** (for the built-in `node:sqlite`).

```bash
cd webring-directory
npm test                     # unit + end-to-end tests, no network needed
ADMIN_TOKEN=dev-token npm start
# open http://localhost:8080
```

There is nothing to install: there are no dependencies. Production uses the same command.

### Environment

| Variable | Default | Notes |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `DATABASE_PATH` | `data/directory.db` | SQLite file; use a persistent volume |
| `ADMIN_TOKEN` | *(unset)* | Enables admin endpoints; use a long random string |
| `TRUST_PROXY` | `0` | Set to `1` behind a reverse proxy to read `X-Forwarded-For` |
| `RATE_LIMIT` | `1` | Set to `0` to disable write rate limiting |
| `ALLOW_INSECURE` | `0` | Allow `http://` sites (development/tests only) |
| `ALLOW_PRIVATE_HOSTS` | `0` | Allow private/local addresses (tests only — **never in production**) |

## API

All responses are JSON. Public reads only expose active entries.

### List / search

```http
GET /api/entries?q=photography&limit=24&offset=0
```

```json
{
  "total": 1,
  "entries": [
    {
      "id": "did:web:alice.example",
      "siteUrl": "https://alice.example",
      "did": "did:web:alice.example",
      "handle": "@alice",
      "displayName": "Alice Example",
      "tagline": "Tiny web enthusiast",
      "bio": "I make small sites.",
      "location": "Halifax, NS",
      "avatarUrl": "https://alice.example/media/avatar.jpg",
      "interests": ["indie web", "photography"],
      "links": [{ "label": "Blog", "url": "https://alice.example/blog" }],
      "profileUpdatedAt": "2026-01-01T00:00:00.000Z",
      "verifiedAt": "2026-01-02T00:00:00.000Z",
      "updatedAt": "2026-01-02T00:00:00.000Z"
    }
  ]
}
```

Search uses SQLite FTS5 over display name, handle, tagline, bio, location and interests,
falling back to `LIKE` if FTS is unavailable.

### Add or refresh

```bash
curl -X POST http://localhost:8080/api/entries \
  -H 'content-type: application/json' \
  --data '{"siteUrl":"https://alice.example"}'
```

`201` for a new entry, `200` for a refreshed one. The site is fetched and verified first; a
failed or invalid site is never written.

You can also refresh one existing entry:

```http
POST /api/entries/:did/refresh
```

### Delete

Removal is authorised by a short-lived nonce signed with the site's Ed25519 private key.

The simplest path is the removal page at `/remove`:

1. Open `https://directory.example/remove` and enter your site URL. The page issues a nonce
   and shows the command to run on the machine that holds your key.
2. Run the helper with the nonce shown on the page and `--link`:

   ```bash
   node scripts/sign-request.js \
     --site-url https://alice.example \
     --nonce <nonce> \
     --dir https://directory.example \
     --key /path/to/private-key.pem \
     --link
   ```

   It signs the request and prints a `…/remove#request=…` link. Open it, check the site it
   names, and confirm. (Omit `--nonce` and the helper will fetch one from `--dir` itself.) The
   signed request travels in the URL fragment, so treat the link as a short-lived one-time
   link. This is the same signed request Webring Studio will send once its “Leave this
   directory” action lands.

You can also work against the API directly. Get a nonce:

```bash
curl https://directory.example/api/nonce
# {"nonce":"…","expiresAt":"…"}
```

Then sign and POST it:

```bash
node scripts/sign-request.js \
  --site-url https://alice.example \
  --did did:web:alice.example \
  --nonce <nonce> \
  --key /path/to/private-key.pem
```

The helper prints the JSON body. POST it to `/api/entries/<encoded did>/remove`. Use
`--dir https://directory.example` to fetch the nonce automatically, `--curl` to print a
ready-to-run curl command, or `--link` to print a link to the removal page carrying the
signed request.

The signature covers `{action:"remove", siteUrl, did, nonce, createdAt}`. The request must be
less than 10 minutes old and the nonce is single-use. The key never leaves the owner's
machine.

> **Studio integration:** the desktop app keeps its private key in the OS keychain. A future
> “Leave this directory” action should sign this payload and POST it from Studio. Until then,
> owners who cannot access their key can ask the operator to remove them, or stop publishing
> `api/profile.json`; after seven failed refreshes the entry is hidden as `stale`.

### Admin

Admin requests need `Authorization: Bearer $ADMIN_TOKEN`.

```http
POST   /api/admin/entries/:did/status   {"status":"active|blocked|stale"}
DELETE /api/admin/entries/:did
POST   /api/admin/refresh               {"limit":10}
```

Blocked entries are hidden from the public API and page and are never auto-unblocked by a
normal refresh. `refresh` checks up to 25 entries per call (oldest first) and returns
`{checked, updated, failed}`.

### Health

```http
GET /api/healthz
```

## Keeping entries fresh

Run a cron sweep against the database:

```bash
DATABASE_PATH=/var/lib/webring-directory/directory.db npm run refresh
```

`scripts/refresh.js` verifies each crawlable entry again, updates changed profiles, and
records failures. After seven consecutive failures an entry becomes `stale` and disappears
from the public list; a later successful refresh makes it active again. Blocked entries are
never touched.

The same work can be done in small batches over HTTP:

```bash
curl -X POST https://directory.example/api/admin/refresh \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  --data '{"limit":10}'
```

## Deployment

### Recommended: Fly.io

A single small machine with a persistent volume is enough for a directory of this size, and
you get TLS and a stable hostname without managing a server.

```bash
fly launch --no-deploy --name webring-directory --region yyz
fly volumes create webring_data --region yyz --size 1
fly secrets set ADMIN_TOKEN="$(openssl rand -hex 32)"
fly deploy
fly open
```

`fly.toml` already mounts a volume at `/data` and sets `DATABASE_PATH=/data/directory.db`.
Keep **one** machine attached to the volume; SQLite is not multi-writer. Put the volume and
the machine in the same region.

Run the refresh sweep from cron, a GitHub Action, or a scheduled machine:

```bash
fly ssh console -C "node scripts/refresh.js"
```

For a zero-cost alternative, a **Hetzner CX22 VPS** (or any small VPS) with Caddy works well:

```caddyfile
directory.example {
  reverse_proxy 127.0.0.1:8080
}
```

```cron
*/30 * * * * cd /srv/webring-directory && DATABASE_PATH=/var/lib/webring-directory/directory.db node scripts/refresh.js >> /var/log/webring-refresh.log 2>&1
```

Cloudflare Workers + D1 is also viable, but the storage and fetch layers here are written for
Node; porting them is more work than running this container.

### Docker

```bash
docker build -t webring-directory .
docker run --rm -p 8080:8080 \
  -e ADMIN_TOKEN=dev-token \
  -v "$PWD/data:/data" \
  webring-directory
```

## Security notes

- **SSRF guard.** Only `https://` URLs are fetched in production. Every hostname is resolved
  and *every* returned address must be globally routable; loopback, RFC1918, CGNAT,
  link-local, multicast, documentation and IPv6 transition ranges are refused. DNS is checked
  in the socket's own `lookup` callback, so the address that is validated is the address that
  is connected to. Redirects are followed manually (max 3) and re-validated.
- **Limits.** 8 s timeout, 2 MB per document, 64 KB request bodies, bounded field lengths.
- **Rate limiting.** 30 write requests per IP per hour by default. Behind a proxy, set
  `TRUST_PROXY=1` so the limit uses the forwarded address.
- **No HTML injection.** The UI builds nodes with `textContent`; profile text is never
  rendered as HTML. A strict CSP is sent with the page, and links are restricted to
  `http(s)`.
- **Admin token** is compared in constant time. Admin endpoints are disabled entirely when
  `ADMIN_TOKEN` is unset.
- **Residual risk:** DNS rebinding is mitigated per connection but not eliminated for
  multi-step fetches (manifest → DID → profile each resolve again). All fetched documents are
  public site files; no credentials are sent. Do not run with `ALLOW_PRIVATE_HOSTS=1` on a
  public host.

### What is stored

Only the public fields already published by the site: display name, handle, tagline, bio,
location, avatar/banner URLs, interests, custom links, site URL, `did`, the public key,
timestamps and verification/refresh state. No private keys, no email addresses, no visitor
data, no cookies.

## Relationship to Webring Studio

This is a separate service. It does not modify Studio or the published files, and it does not
need to be trusted by Studio clients. It is a convenience index over data the owner has
already chosen to publish, with cryptographic proof of ownership at add/delete time.

Licensed under **GPL-3.0-or-later**, matching Webring Studio. The verification code is an
independent implementation of Studio's documented signing scheme, not a copy of its source.
