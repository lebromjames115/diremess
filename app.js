'use strict';
/**
 * Relay client.
 *
 * Security model:
 *  - Each account has an ECDH (P-256) keypair generated IN THE BROWSER.
 *  - The private key is exported to a JWK and kept only in this browser's
 *    localStorage. It is never sent anywhere.
 *  - The public key is uploaded to the server so other users can find it.
 *  - To message someone, we derive a shared AES-256-GCM key from
 *    (my private key, their public key) via ECDH. The same shared key
 *    falls out of (their private key, my public key) on their side.
 *  - Every message is encrypted with that shared key before it is sent.
 *    The server only ever stores/relays the ciphertext + IV.
 *
 * Honest limitations (see README.md for the full list):
 *  - No forward secrecy / double-ratchet like Signal — this is a single
 *    static shared key per contact pair, not a rotating one.
 *  - No multi-device sync: each browser you log in from generates its own
 *    identity. Verify safety codes again if a contact's key ever changes.
 *  - The server *could* lie about someone's public key (a MITM). The
 *    "Verify safety code" feature is how you detect that — compare the
 *    code with your contact over a channel other than Relay itself.
 */

// ---------------- crypto helpers ----------------
const enc = new TextEncoder();
const dec = new TextDecoder();

function bufToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function base64ToBuf(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function generateIdentity() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  return { publicJwk, privateJwk };
}
function importPrivateKey(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
}
function importPublicKey(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
}
function deriveSharedKey(myPrivateKey, theirPublicKey) {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: theirPublicKey },
    myPrivateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
async function encryptText(sharedKey, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, sharedKey, enc.encode(plaintext));
  return { ciphertext: bufToBase64(ciphertext), iv: bufToBase64(iv) };
}
async function decryptText(sharedKey, ciphertextB64, ivB64) {
  const plaintextBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(base64ToBuf(ivB64)) },
    sharedKey,
    base64ToBuf(ciphertextB64)
  );
  return dec.decode(plaintextBuf);
}
async function safetyCode(myPublicJwk, theirPublicJwk) {
  // Order-independent so both sides compute the same code.
  const a = String(myPublicJwk.x) + String(myPublicJwk.y);
  const b = String(theirPublicJwk.x) + String(theirPublicJwk.y);
  const combined = [a, b].sort().join('|');
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(combined));
  const bytes = new Uint8Array(hashBuf);
  const groups = [];
  for (let i = 0; i < 12; i++) groups.push(String(bytes[i]).padStart(3, '0'));
  return groups.join(' ');
}

// ---------------- storage helpers (namespaced per local username) ----------------
const store = {
  get(key, fallback = null) {
    try {
      const raw = localStorage.getItem(key);
      return raw === null ? fallback : JSON.parse(raw);
    } catch { return fallback; }
  },
  set(key, value) { localStorage.setItem(key, JSON.stringify(value)); },
  remove(key) { localStorage.removeItem(key); },
};

const keys = {
  session: 'relay:session',
  identity: (u) => `relay:identity:${u}`,
  contacts: (u) => `relay:contacts:${u}`,
  history: (u, c) => `relay:history:${u}:${c}`,
  unread: (u) => `relay:unread:${u}`,
};

// ---------------- app state ----------------
const state = {
  username: null,
  token: null,
  myPublicJwk: null,
  myPrivateKey: null, // CryptoKey
  contacts: [],        // [username, ...]
  unread: {},           // { contact: true }
  activeContact: null,
  sharedKeyCache: new Map(),  // contact -> CryptoKey
  publicKeyCache: new Map(),  // contact -> jwk
  polling: false,
};

// ---------------- API helpers ----------------
// GitHub Pages only serves static files, so /api/* has to live on a separate
// backend. Point this at wherever you deploy relay-server (see README).
const API_BASE = 'https://relay-server-nig5.onrender.com';

async function api(path, { method = 'GET', body, auth = true } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (auth && state.token) headers['Authorization'] = `Bearer ${state.token}`;
  const res = await fetch(API_BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  let data = {};
  try { data = await res.json(); } catch { /* ignore empty body */ }
  if (res.status === 401 && auth) {
    handleSessionExpired();
    throw new Error(data.error || 'session expired');
  }
  if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
  return data;
}

// ---------------- DOM refs ----------------
const $ = (id) => document.getElementById(id);
const authScreen = $('auth-screen');
const appScreen = $('app-screen');
const tabLogin = $('tab-login');
const tabRegister = $('tab-register');
const authForm = $('auth-form');
const usernameInput = $('username-input');
const passwordInput = $('password-input');
const authError = $('auth-error');
const authSubmit = $('auth-submit');
const whoamiUsername = $('whoami-username');
const newConvoForm = $('new-convo-form');
const newConvoInput = $('new-convo-input');
const newConvoError = $('new-convo-error');
const contactListEl = $('contact-list');
const conversationEmpty = $('conversation-empty');
const conversationActive = $('conversation-active');
const contactNameEl = $('contact-name');
const messageLogEl = $('message-log');
const composer = $('composer');
const composerInput = $('composer-input');
const logoutBtn = $('logout-btn');
const forgetDeviceBtn = $('forget-device-btn');
const showFingerprintBtn = $('show-fingerprint-btn');
const backToContactsBtn = $('back-to-contacts-btn');
const fingerprintPanel = $('fingerprint-panel');
const fingerprintValue = $('fingerprint-value');
const fingerprintContactName = $('fingerprint-contact-name');

let authMode = 'login';

// ---------------- auth screen wiring ----------------
tabLogin.addEventListener('click', () => setAuthMode('login'));
tabRegister.addEventListener('click', () => setAuthMode('register'));

function setAuthMode(mode) {
  authMode = mode;
  tabLogin.classList.toggle('active', mode === 'login');
  tabRegister.classList.toggle('active', mode === 'register');
  authSubmit.textContent = mode === 'login' ? 'Log in' : 'Create account';
  passwordInput.autocomplete = mode === 'login' ? 'current-password' : 'new-password';
  authError.hidden = true;
}

authForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  authError.hidden = true;
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  authSubmit.disabled = true;
  try {
    const data = authMode === 'login'
      ? await api('/api/login', { method: 'POST', body: { username, password }, auth: false })
      : await api('/api/register', { method: 'POST', body: { username, password }, auth: false });
    await onAuthenticated(data.username, data.token);
  } catch (err) {
    authError.textContent = err.message;
    authError.hidden = false;
  } finally {
    authSubmit.disabled = false;
  }
});

async function onAuthenticated(username, token) {
  state.username = username;
  state.token = token;
  store.set(keys.session, { username, token });

  // Load or create this browser's identity for this account.
  let identity = store.get(keys.identity(username));
  if (!identity) {
    identity = await generateIdentity();
    store.set(keys.identity(username), identity);
    await api('/api/publickey', { method: 'POST', body: { publicKey: identity.publicJwk } });
  }
  state.myPublicJwk = identity.publicJwk;
  state.myPrivateKey = await importPrivateKey(identity.privateJwk);

  state.contacts = store.get(keys.contacts(username), []);
  state.unread = store.get(keys.unread(username), {});
  state.activeContact = null;

  showApp();
  startPolling();
}

function handleSessionExpired() {
  state.token = null;
  store.remove(keys.session);
  showAuth();
}

// ---------------- screen switching ----------------
function showAuth() {
  authScreen.hidden = false;
  appScreen.hidden = true;
  passwordInput.value = '';
}
function showApp() {
  authScreen.hidden = true;
  appScreen.hidden = false;
  appScreen.classList.remove('show-conversation');
  whoamiUsername.textContent = state.username;
  renderContactList();
  renderConversation();
}

// ---------------- contact list ----------------
function persistContacts() { store.set(keys.contacts(state.username), state.contacts); }
function persistUnread() { store.set(keys.unread(state.username), state.unread); }

function addContact(contact) {
  if (!state.contacts.includes(contact)) {
    state.contacts.unshift(contact);
    persistContacts();
  }
}

function lastPreview(contact) {
  const history = store.get(keys.history(state.username, contact), []);
  if (!history.length) return '';
  const last = history[history.length - 1];
  const prefix = last.from === state.username ? 'You: ' : '';
  return prefix + last.text;
}

function renderContactList() {
  contactListEl.innerHTML = '';
  for (const contact of state.contacts) {
    const li = document.createElement('li');
    li.className = 'contact-item' + (contact === state.activeContact ? ' active' : '');
    li.tabIndex = 0;

    const row = document.createElement('div');
    row.className = 'contact-row';

    const avatar = document.createElement('span');
    avatar.className = 'contact-avatar';
    avatar.textContent = contact.slice(0, 2);

    const cell = document.createElement('div');
    cell.className = 'contact-name-cell';
    const name = document.createElement('span');
    name.className = 'name';
    name.textContent = contact;
    const preview = document.createElement('span');
    preview.className = 'preview';
    preview.textContent = lastPreview(contact);
    cell.append(name, preview);

    row.append(avatar, cell);
    li.append(row);

    if (state.unread[contact]) {
      const dot = document.createElement('span');
      dot.className = 'unread-dot';
      li.append(dot);
    }

    li.addEventListener('click', () => openConversation(contact));
    li.addEventListener('keydown', (e) => { if (e.key === 'Enter') openConversation(contact); });
    contactListEl.append(li);
  }
}

// ---------------- new conversation ----------------
newConvoForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  newConvoError.hidden = true;
  const target = newConvoInput.value.trim();
  if (!target) return;
  if (target === state.username) {
    newConvoError.textContent = "That's you.";
    newConvoError.hidden = false;
    return;
  }
  newConvoInput.disabled = true;
  const originalPlaceholder = newConvoInput.placeholder;
  newConvoInput.placeholder = 'Looking up user…';
  try {
    await fetchPublicKey(target); // throws if the user doesn't exist / has no key yet
    addContact(target);
    newConvoInput.value = '';
    renderContactList();
    openConversation(target);
  } catch (err) {
    newConvoError.textContent = err.message;
    newConvoError.hidden = false;
  } finally {
    newConvoInput.disabled = false;
    newConvoInput.placeholder = originalPlaceholder;
  }
});

// ---------------- key + shared-key management ----------------
async function fetchPublicKey(username) {
  if (state.publicKeyCache.has(username)) return state.publicKeyCache.get(username);
  const data = await api(`/api/publickey/${encodeURIComponent(username)}`, { auth: false });
  state.publicKeyCache.set(username, data.publicKey);
  return data.publicKey;
}

async function getSharedKey(contact) {
  if (state.sharedKeyCache.has(contact)) return state.sharedKeyCache.get(contact);
  const theirJwk = await fetchPublicKey(contact);
  const theirKey = await importPublicKey(theirJwk);
  const shared = await deriveSharedKey(state.myPrivateKey, theirKey);
  state.sharedKeyCache.set(contact, shared);
  return shared;
}

// ---------------- conversation view ----------------
function openConversation(contact) {
  state.activeContact = contact;
  delete state.unread[contact];
  persistUnread();
  fingerprintPanel.hidden = true;
  appScreen.classList.add('show-conversation');
  renderContactList();
  renderConversation();
  composerInput.focus();
}

backToContactsBtn.addEventListener('click', () => {
  appScreen.classList.remove('show-conversation');
});

function appendHistory(contact, entry) {
  const key = keys.history(state.username, contact);
  const history = store.get(key, []);
  history.push(entry);
  store.set(key, history);
}

function renderConversation() {
  if (!state.activeContact) {
    conversationEmpty.hidden = false;
    conversationActive.hidden = true;
    return;
  }
  conversationEmpty.hidden = true;
  conversationActive.hidden = false;
  contactNameEl.textContent = state.activeContact;

  const history = store.get(keys.history(state.username, state.activeContact), []);
  messageLogEl.innerHTML = '';
  for (const entry of history) {
    const div = document.createElement('div');
    div.className = 'message ' + (entry.from === state.username ? 'mine' : 'theirs');
    div.textContent = entry.text;
    const meta = document.createElement('span');
    meta.className = 'meta';
    meta.textContent = new Date(entry.ts).toLocaleString();
    div.append(meta);
    messageLogEl.append(div);
  }
  messageLogEl.scrollTop = messageLogEl.scrollHeight;
}

showFingerprintBtn.addEventListener('click', async () => {
  if (!state.activeContact) return;
  if (!fingerprintPanel.hidden) { fingerprintPanel.hidden = true; return; }
  const theirJwk = await fetchPublicKey(state.activeContact);
  fingerprintContactName.textContent = state.activeContact;
  fingerprintValue.textContent = await safetyCode(state.myPublicJwk, theirJwk);
  fingerprintPanel.hidden = false;
});

// auto-grow the composer textarea a little
composerInput.addEventListener('input', () => {
  composerInput.style.height = 'auto';
  composerInput.style.height = Math.min(composerInput.scrollHeight, 140) + 'px';
});
composerInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    composer.requestSubmit();
  }
});

composer.addEventListener('submit', async (e) => {
  e.preventDefault();
  const text = composerInput.value.trim();
  if (!text || !state.activeContact) return;
  const contact = state.activeContact;
  composerInput.value = '';
  composerInput.style.height = 'auto';
  try {
    const sharedKey = await getSharedKey(contact);
    const { ciphertext, iv } = await encryptText(sharedKey, text);
    await api('/api/send', { method: 'POST', body: { to: contact, ciphertext, iv } });
    appendHistory(contact, { from: state.username, text, ts: Date.now() });
    renderContactList();
    if (state.activeContact === contact) renderConversation();
  } catch (err) {
    appendHistory(contact, { from: 'system', text: `Not sent: ${err.message}`, ts: Date.now() });
    if (state.activeContact === contact) renderConversation();
  }
});

// ---------------- polling for incoming mail ----------------
async function startPolling() {
  if (state.polling) return;
  state.polling = true;
  pollLoop();
}

async function pollLoop() {
  while (state.token) {
    let data;
    try {
      data = await api('/api/poll');
    } catch {
      // If logged out mid-poll, stop; otherwise back off briefly and retry.
      if (!state.token) break;
      await sleep(2000);
      continue;
    }
    for (const msg of data.messages || []) {
      await handleIncoming(msg);
    }
    await sleep(3000);
  }
  state.polling = false;
}
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function handleIncoming(msg) {
  const { from, ciphertext, iv, ts } = msg;
  try {
    const sharedKey = await getSharedKey(from);
    const text = await decryptText(sharedKey, ciphertext, iv);
    addContact(from);
    appendHistory(from, { from, text, ts });
    if (state.activeContact !== from) {
      state.unread[from] = true;
      persistUnread();
    }
    renderContactList();
    if (state.activeContact === from) renderConversation();
  } catch (err) {
    console.error('Failed to decrypt message from', from, err);
  }
}

// ---------------- logout / forget device ----------------
logoutBtn.addEventListener('click', () => {
  state.token = null;
  state.username = null;
  store.remove(keys.session);
  showAuth();
});

forgetDeviceBtn.addEventListener('click', () => {
  if (!state.username) return;
  const ok = confirm(
    `This deletes your encryption keys and message history for "${state.username}" from THIS BROWSER only. ` +
    `Your account will still exist, but this device will no longer be able to read past messages, ` +
    `and contacts will need to re-verify your safety code. Continue?`
  );
  if (!ok) return;
  const username = state.username;
  store.remove(keys.identity(username));
  store.remove(keys.contacts(username));
  store.remove(keys.unread(username));
  for (const contact of state.contacts) store.remove(keys.history(username, contact));
  store.remove(keys.session);
  state.token = null;
  state.username = null;
  showAuth();
});

// ---------------- boot ----------------
(async function boot() {
  const session = store.get(keys.session);
  if (session && session.token && session.username) {
    try {
      await onAuthenticated(session.username, session.token);
      return;
    } catch {
      store.remove(keys.session);
    }
  }
  showAuth();
})();
