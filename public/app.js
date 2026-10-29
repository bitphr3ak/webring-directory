const PAGE_SIZE = 24;

const state = {
  query: '',
  offset: 0,
  total: 0,
  entries: [],
  loading: false,
  requestId: 0
};

const searchInput = document.getElementById('search');
const entriesEl = document.getElementById('entries');
const countEl = document.getElementById('count');
const emptyEl = document.getElementById('empty');
const statusEl = document.getElementById('status');
const moreButton = document.getElementById('more');
const addForm = document.getElementById('add-form');
const siteUrlInput = document.getElementById('site-url');
const formMessage = document.getElementById('form-message');

function httpUrl(value) {
  if (typeof value !== 'string') return '';
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : '';
  } catch {
    return '';
  }
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function initials(name) {
  const words = String(name || '?').trim().split(/\s+/).slice(0, 2);
  return words.map((word) => word[0] || '').join('').toUpperCase() || '?';
}

function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleDateString(undefined, { dateStyle: 'medium' });
}

function renderAvatar(entry) {
  const avatarUrl = httpUrl(entry.avatarUrl);
  if (!avatarUrl) {
    return element('div', 'avatar avatar-fallback', initials(entry.displayName));
  }
  const image = document.createElement('img');
  image.className = 'avatar';
  image.src = avatarUrl;
  image.alt = '';
  image.loading = 'lazy';
  image.referrerPolicy = 'no-referrer';
  image.addEventListener('error', () => {
    image.replaceWith(element('div', 'avatar avatar-fallback', initials(entry.displayName)));
  });
  return image;
}

function renderCard(entry) {
  const card = element('article', 'entry');

  const header = element('div', 'entry-head');
  header.append(renderAvatar(entry));

  const identity = element('div', 'identity');
  const name = element('h3', 'name');
  const siteUrl = httpUrl(entry.siteUrl);
  if (siteUrl) {
    const link = element('a', null, entry.displayName || new URL(siteUrl).hostname);
    link.href = siteUrl;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    name.append(link);
  } else {
    name.textContent = entry.displayName || 'Unnamed';
  }
  identity.append(name);
  if (entry.handle) identity.append(element('p', 'handle', entry.handle));
  header.append(identity);
  card.append(header);

  if (entry.tagline) card.append(element('p', 'tagline', entry.tagline));
  if (entry.bio) card.append(element('p', 'bio', entry.bio));

  if (entry.location) {
    const meta = element('p', 'meta');
    meta.append(element('span', 'meta-label', 'Location'));
    meta.append(element('span', null, entry.location));
    card.append(meta);
  }

  if (Array.isArray(entry.interests) && entry.interests.length) {
    const chips = element('ul', 'chips');
    for (const interest of entry.interests.slice(0, 12)) {
      chips.append(element('li', 'chip', interest));
    }
    card.append(chips);
  }

  if (Array.isArray(entry.links) && entry.links.length) {
    const links = element('ul', 'links');
    for (const item of entry.links.slice(0, 8)) {
      const url = httpUrl(item && item.url);
      if (!url) continue;
      const li = document.createElement('li');
      const anchor = element('a', null, (item && item.label) || new URL(url).hostname);
      anchor.href = url;
      anchor.target = '_blank';
      anchor.rel = 'noopener noreferrer nofollow';
      li.append(anchor);
      links.append(li);
    }
    if (links.childElementCount) card.append(links);
  }

  const footer = element('div', 'entry-foot');
  if (siteUrl) {
    const anchor = element('a', 'visit', `Visit ${new URL(siteUrl).hostname}`);
    anchor.href = siteUrl;
    anchor.target = '_blank';
    anchor.rel = 'noopener noreferrer';
    footer.append(anchor);
  }
  if (entry.verifiedAt) {
    footer.append(element('span', 'verified', `Verified ${formatDate(entry.verifiedAt)}`));
  }
  card.append(footer);

  return card;
}

function render() {
  entriesEl.replaceChildren();
  const fragment = document.createDocumentFragment();
  for (const entry of state.entries) fragment.append(renderCard(entry));
  entriesEl.append(fragment);

  countEl.textContent = state.total ? `${state.total.toLocaleString()} total` : '';
  emptyEl.hidden = state.total !== 0;
  emptyEl.textContent = state.query
    ? 'No profiles match that search yet.'
    : 'The directory is empty. Add the first site.';
  moreButton.hidden = state.entries.length >= state.total;
}

async function load({ reset = false } = {}) {
  const requestId = ++state.requestId;
  state.loading = true;
  if (reset) {
    state.offset = 0;
    state.entries = [];
  }
  statusEl.textContent = 'Loading…';

  const params = new URLSearchParams({
    limit: String(PAGE_SIZE),
    offset: String(state.offset)
  });
  if (state.query) params.set('q', state.query);

  try {
    const response = await fetch(`/api/entries?${params}`, { headers: { accept: 'application/json' } });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.message || `Request failed (${response.status}).`);
    if (requestId !== state.requestId) return;

    const incoming = Array.isArray(data.entries) ? data.entries : [];
    state.total = Number(data.total) || 0;
    state.entries = reset ? incoming : state.entries.concat(incoming);
    state.offset = state.entries.length;
    statusEl.textContent = '';
    render();
  } catch (err) {
    if (requestId !== state.requestId) return;
    statusEl.textContent = err.message || 'Could not load the directory.';
  } finally {
    if (requestId === state.requestId) state.loading = false;
  }
}

let searchTimer;
searchInput.addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    state.query = searchInput.value.trim();
    load({ reset: true });
  }, 250);
});

moreButton.addEventListener('click', () => {
  if (state.loading) return;
  load();
});

addForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const siteUrl = siteUrlInput.value.trim();
  if (!siteUrl) return;

  const button = addForm.querySelector('button[type="submit"]');
  button.disabled = true;
  formMessage.textContent = 'Fetching and verifying your site…';
  formMessage.className = 'form-message';

  try {
    const response = await fetch('/api/entries', {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ siteUrl })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.message || `Request failed (${response.status}).`);

    const name = data.entry && data.entry.displayName;
    formMessage.textContent = name
      ? `${name} is listed${response.status === 201 ? '' : ' and up to date'}.`
      : 'Site verified and listed.';
    formMessage.className = 'form-message success';
    siteUrlInput.value = '';
    state.query = '';
    searchInput.value = '';
    await load({ reset: true });
  } catch (err) {
    formMessage.textContent = err.message || 'Could not add that site.';
    formMessage.className = 'form-message error';
  } finally {
    button.disabled = false;
  }
});

load({ reset: true });
