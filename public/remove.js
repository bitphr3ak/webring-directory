const startPanel = document.getElementById('start-panel');
const startForm = document.getElementById('start-form');
const siteUrlInput = document.getElementById('site-url');
const startMessage = document.getElementById('start-message');
const instructions = document.getElementById('instructions');
const commandEl = document.getElementById('command');

const pastePanel = document.getElementById('paste-panel');
const pasteForm = document.getElementById('paste-form');
const requestInput = document.getElementById('request-json');
const pasteMessage = document.getElementById('paste-message');

const confirmPanel = document.getElementById('confirm-panel');
const confirmForm = document.getElementById('confirm-form');
const confirmName = document.getElementById('confirm-name');
const confirmSite = document.getElementById('confirm-site');
const confirmDid = document.getElementById('confirm-did');
const confirmCreated = document.getElementById('confirm-created');
const confirmMessage = document.getElementById('confirm-message');

let pending = null;

function setMessage(node, text, kind = '') {
  node.textContent = text;
  node.className = kind ? `form-message ${kind}` : 'form-message';
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function isHttpUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:';
  } catch {
    return false;
  }
}

function validateRequest(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return 'That does not look like a signed request.';
  }
  for (const field of ['siteUrl', 'nonce', 'createdAt', 'signature']) {
    if (typeof body[field] !== 'string' || !body[field].trim()) {
      return `The request is missing ${field}.`;
    }
  }
  if (!isHttpUrl(body.siteUrl)) return 'The request has an invalid siteUrl.';
  if (typeof body.did !== 'string' || !body.did.startsWith('did:web:')) {
    return 'The request is missing a did:web identifier.';
  }
  if (!Number.isFinite(Date.parse(body.createdAt))) {
    return 'The request has an invalid createdAt timestamp.';
  }
  return '';
}

function decodeFragment(hash) {
  const params = new URLSearchParams(String(hash || '').replace(/^#/, ''));
  const encoded = params.get('request');
  if (!encoded) return null;
  const base64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

async function loadDisplayName(body) {
  try {
    const response = await fetch(`/api/entries/${encodeURIComponent(body.did)}`, {
      headers: { accept: 'application/json' }
    });
    if (!response.ok) return;
    const data = await response.json();
    if (pending === body && data.entry && data.entry.displayName) {
      confirmName.textContent = data.entry.displayName;
    }
  } catch {
    // the hostname fallback is enough
  }
}

function showConfirm(body) {
  pending = body;
  confirmName.textContent = new URL(body.siteUrl).hostname;
  confirmSite.textContent = body.siteUrl;
  confirmDid.textContent = body.did;
  const created = new Date(body.createdAt);
  confirmCreated.textContent = Number.isNaN(created.getTime())
    ? body.createdAt
    : created.toLocaleString();
  startPanel.hidden = true;
  pastePanel.hidden = true;
  confirmPanel.hidden = false;
  confirmForm.hidden = false;
  setMessage(confirmMessage, '');
  loadDisplayName(body);
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function review(body) {
  const problem = validateRequest(body);
  if (problem) {
    setMessage(pasteMessage, problem, 'error');
    return false;
  }
  showConfirm(body);
  return true;
}

startForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const siteUrl = siteUrlInput.value.trim();
  if (!siteUrl) return;

  const button = startForm.querySelector('button[type="submit"]');
  button.disabled = true;
  setMessage(startMessage, 'Getting a nonce…');

  try {
    const response = await fetch('/api/nonce', { headers: { accept: 'application/json' } });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.nonce) {
      throw new Error(data.message || `Request failed (${response.status}).`);
    }

    const command = [
      'node scripts/sign-request.js',
      `  --site-url ${shellQuote(siteUrl)}`,
      `  --nonce ${shellQuote(data.nonce)}`,
      `  --dir ${shellQuote(location.origin)}`,
      '  --key /path/to/private-key.pem',
      '  --link'
    ].join(' \\\n');

    commandEl.textContent = command;
    instructions.hidden = false;
    const expires = data.expiresAt ? new Date(data.expiresAt) : null;
    setMessage(
      startMessage,
      expires && !Number.isNaN(expires.getTime())
        ? `Nonce issued. It expires at ${expires.toLocaleTimeString()}.`
        : 'Nonce issued.',
      'success'
    );
  } catch (err) {
    setMessage(startMessage, err.message || 'Could not get a nonce.', 'error');
  } finally {
    button.disabled = false;
  }
});

pasteForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const raw = requestInput.value.trim();
  if (!raw) return;

  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    setMessage(pasteMessage, 'That is not valid JSON.', 'error');
    return;
  }

  review(body);
});

confirmForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!pending) return;

  const button = confirmForm.querySelector('button[type="submit"]');
  button.disabled = true;
  setMessage(confirmMessage, 'Removing…');

  try {
    const response = await fetch(`/api/entries/${encodeURIComponent(pending.did)}/remove`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        siteUrl: pending.siteUrl,
        did: pending.did,
        nonce: pending.nonce,
        createdAt: pending.createdAt,
        signature: pending.signature
      })
    });

    if (response.status === 204) {
      pending = null;
      confirmForm.hidden = true;
      history.replaceState(null, '', '/remove');
      setMessage(confirmMessage, 'Removed. That site is no longer listed in the directory.', 'success');
      return;
    }

    const data = await response.json().catch(() => ({}));
    throw new Error(data.message || `Request failed (${response.status}).`);
  } catch (err) {
    setMessage(confirmMessage, err.message || 'Could not remove that entry.', 'error');
    button.disabled = false;
  }
});

let fromHash = null;
try {
  fromHash = decodeFragment(location.hash);
} catch {
  setMessage(pasteMessage, 'That removal link is malformed.', 'error');
  pastePanel.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

if (fromHash && !review(fromHash)) {
  pastePanel.scrollIntoView({ behavior: 'smooth', block: 'center' });
}
