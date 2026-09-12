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
 *  - Group chats reuse the exact same pairwise keys: a group message is
 *    encrypted separately for each other member with the shared key you
 *    already have with them, and sent as a batch ("fan-out"). Each member
 *    decrypts their own copy with the sender's pairwise key, same as a DM.
 *    There is no separate group key and no server-side crypto change —
 *    the server just validates membership and routes each ciphertext copy.
 *    One honest consequence: the server does see (and must see, to route
 *    correctly) the group's name and member list, even though it never
 *    sees message content. Treat group membership like your contact list —
 *    not confidential from Relay, but message text always is.
 *
 * Honest limitations (see README.md for the full list):
 *  - No forward secrecy / double-ratchet like Signal — this is a single
 *    static shared key per contact pair, not a rotating one.
 *  - No multi-device sync: each browser you log in from generates its own
 *    identity. Verify safety codes again if a contact's key ever changes.
 *  - The server *could* lie about someone's public key (a MITM). The
 *    "Verify safety code" feature is how you detect that — compare the
 *    code with your contact over a channel other than Relay itself. In a
 *    group, verify each member's code individually.
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
  contacts: (u) => `relay:contacts:${u}`, // legacy pre-groups format, migrated on load
  conversations: (u) => `relay:conversations:${u}`,
  history: (u, convKey) => `relay:history:${u}:${convKey}`,
  unread: (u) => `relay:unread:${u}`,
};

// ---------------- conversation identity helpers ----------------
// A conversation is either { type: 'dm', id: username } or
// { type: 'group', id: groupId, name, members: [username,...] }.
// Its storage key ("convKey") is the plain username for a DM, or
// "group:<id>" for a group — usernames can't contain ':', so these can't
// collide.
function convKey(conv) {
  return conv.type === 'group' ? `group:${conv.id}` : conv.id;
}
function isGroupKey(key) {
  return key.startsWith('group:');
}

// ---------------- app state ----------------
const state = {
  username: null,
  token: null,
  myPublicJwk: null,
  myPrivateKey: null,     // CryptoKey
  conversations: [],       // [{type:'dm', id} | {type:'group', id, name, members}]
  unread: {},               // { convKey: true }
  activeConv: null,        // the conversation object currently open, or null
  sharedKeyCache: new Map(), // username -> CryptoKey (pairwise, works for DMs and group fan-out)
  publicKeyCache: new Map(), // username -> jwk
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
const modeDmBtn = $('mode-dm');
const modeGroupBtn = $('mode-group');
const newConvoForm = $('new-convo-form');
const newConvoInput = $('new-convo-input');
const newGroupForm = $('new-group-form');
const groupNameInput = $('group-name-input');
const groupMemberInput = $('group-member-input');
const groupMemberChips = $('group-member-chips');
const createGroupBtn = $('create-group-btn');
const newConvoError = $('new-convo-error');
const contactListEl = $('contact-list');
const conversationEmpty = $('conversation-empty');
const conversationActive = $('conversation-active');
const contactNameEl = $('contact-name');
const groupMetaEl = $('group-meta');
const addMemberBtn = $('add-member-btn');
const messageLogEl = $('message-log');
const composer = $('composer');
const composerInput = $('composer-input');
const logoutBtn = $('logout-btn');
const forgetDeviceBtn = $('forget-device-btn');
const showFingerprintBtn = $('show-fingerprint-btn');
const backToContactsBtn = $('back-to-contacts-btn');
const fingerprintPanel = $('fingerprint-panel');
const fingerprintValue = $('fingerprint-value');
const fingerprintList = $('fingerprint-list');
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

  // Load conversations, migrating the old flat contacts list if needed.
  let conversations = store.get(keys.conversations(username));
  if (!conversations) {
    const legacyContacts = store.get(keys.contacts(username), []);
    conversations = legacyContacts.map((c) => ({ type: 'dm', id: c }));
    store.set(keys.conversations(username), conversations);
  }
  state.conversations = conversations;
  state.unread = store.get(keys.unread(username), {});
  state.activeConv = null;

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
  renderConversationList();
  renderConversation();
}

// ---------------- conversation list ----------------
function persistConversations() { store.set(keys.conversations(state.username), state.conversations); }
function persistUnread() { store.set(keys.unread(state.username), state.unread); }

// Adds a new conversation, or merges fresh fields (name/members) into an
// existing one — used both when the user starts a chat and when server
// notifications update a group's roster.
function addConversation(type, id, extra = {}) {
  const key = type === 'group' ? `group:${id}` : id;
  const idx = state.conversations.findIndex((c) => convKey(c) === key);
  if (idx === -1) {
    state.conversations.unshift({ type, id, ...extra });
  } else {
    state.conversations[idx] = { ...state.conversations[idx], ...extra };
  }
  persistConversations();
}

function lastPreview(key) {
  const history = store.get(keys.history(state.username, key), []);
  if (!history.length) return '';
  const last = history[history.length - 1];
  const prefix = last.from === state.username ? 'You: ' : (isGroupKey(key) && last.from !== 'system' ? `${last.from}: ` : '');
  return prefix + last.text;
}

function renderConversationList() {
  contactListEl.innerHTML = '';
  for (const conv of state.conversations) {
    const key = convKey(conv);
    const li = document.createElement('li');
    li.className = 'contact-item' + (state.activeConv && convKey(state.activeConv) === key ? ' active' : '');
    li.tabIndex = 0;

    const row = document.createElement('div');
    row.className = 'contact-row';

    const avatar = document.createElement('span');
    avatar.className = 'contact-avatar';
    const label = conv.type === 'group' ? conv.name : conv.id;
    avatar.textContent = (label || '').slice(0, 2);

    const cell = document.createElement('div');
    cell.className = 'contact-name-cell';
    const name = document.createElement('span');
    name.className = 'name';
    name.textContent = label;
    const preview = document.createElement('span');
    preview.className = 'preview';
    preview.textContent = lastPreview(key);
    cell.append(name, preview);

    row.append(avatar, cell);
    li.append(row);

    if (state.unread[key]) {
      const dot = document.createElement('span');
      dot.className = 'unread-dot';
      li.append(dot);
    }

    li.addEventListener('click', () => openConversation(conv));
    li.addEventListener('keydown', (e) => { if (e.key === 'Enter') openConversation(conv); });
    contactListEl.append(li);
  }
}

// ---------------- new conversation (direct) ----------------
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
    addConversation('dm', target);
    newConvoInput.value = '';
    renderConversationList();
    openConversation({ type: 'dm', id: target });
  } catch (err) {
    newConvoError.textContent = err.message;
    newConvoError.hidden = false;
  } finally {
    newConvoInput.disabled = false;
    newConvoInput.placeholder = originalPlaceholder;
  }
});

// ---------------- new conversation (group) ----------------
function setNewConvoMode(mode) {
  modeDmBtn.classList.toggle('active', mode === 'dm');
  modeGroupBtn.classList.toggle('active', mode === 'group');
  newConvoForm.hidden = mode !== 'dm';
  newGroupForm.hidden = mode !== 'group';
  newConvoError.hidden = true;
}
modeDmBtn.addEventListener('click', () => setNewConvoMode('dm'));
modeGroupBtn.addEventListener('click', () => setNewConvoMode('group'));

let pendingGroupMembers = [];

function renderMemberChips() {
  groupMemberChips.innerHTML = '';
  for (const m of pendingGroupMembers) {
    const li = document.createElement('li');
    li.className = 'chip';
    const label = document.createElement('span');
    label.textContent = m;
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'chip-remove';
    remove.setAttribute('aria-label', `Remove ${m}`);
    remove.textContent = '\u00d7';
    remove.addEventListener('click', () => {
      pendingGroupMembers = pendingGroupMembers.filter((x) => x !== m);
      renderMemberChips();
    });
    li.append(label, remove);
    groupMemberChips.append(li);
  }
  createGroupBtn.disabled = !(groupNameInput.value.trim() && pendingGroupMembers.length);
}

function addPendingMember() {
  newConvoError.hidden = true;
  const name = groupMemberInput.value.trim();
  if (!name) return;
  if (name === state.username) {
    newConvoError.textContent = "That's you — you're already in.";
    newConvoError.hidden = false;
    return;
  }
  groupMemberInput.value = '';
  if (pendingGroupMembers.includes(name)) return;
  pendingGroupMembers.push(name);
  renderMemberChips();
}
groupMemberInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    addPendingMember();
  }
});
groupNameInput.addEventListener('input', () => {
  createGroupBtn.disabled = !(groupNameInput.value.trim() && pendingGroupMembers.length);
});

newGroupForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  newConvoError.hidden = true;
  const name = groupNameInput.value.trim();
  if (!name || !pendingGroupMembers.length) return;
  createGroupBtn.disabled = true;
  try {
    const { group } = await api('/api/groups', { method: 'POST', body: { name, members: pendingGroupMembers } });
    addConversation('group', group.id, { name: group.name, members: group.members });
    groupNameInput.value = '';
    pendingGroupMembers = [];
    renderMemberChips();
    renderConversationList();
    setNewConvoMode('dm');
    openConversation({ type: 'group', id: group.id, name: group.name, members: group.members });
  } catch (err) {
    newConvoError.textContent = err.message;
    newConvoError.hidden = false;
  } finally {
    createGroupBtn.disabled = false;
  }
});

addMemberBtn.addEventListener('click', async () => {
  if (!state.activeConv || state.activeConv.type !== 'group') return;
  const username = prompt('Add member — enter their username:');
  if (!username) return;
  const trimmed = username.trim();
  if (!trimmed) return;
  try {
    const { group } = await api(`/api/groups/${encodeURIComponent(state.activeConv.id)}/members`, {
      method: 'POST',
      body: { username: trimmed },
    });
    applyGroupUpdate(group);
  } catch (err) {
    alert(err.message);
  }
});

// Merges a fresh group record (from the server) into local state and
// re-renders anything showing it.
function applyGroupUpdate(group) {
  addConversation('group', group.id, { name: group.name, members: group.members });
  if (state.activeConv && state.activeConv.type === 'group' && state.activeConv.id === group.id) {
    state.activeConv = { type: 'group', id: group.id, name: group.name, members: group.members };
    renderConversation();
  }
  renderConversationList();
}

// ---------------- key + shared-key management ----------------
async function fetchPublicKey(username) {
  if (state.publicKeyCache.has(username)) return state.publicKeyCache.get(username);
  const data = await api(`/api/publickey/${encodeURIComponent(username)}`, { auth: false });
  state.publicKeyCache.set(username, data.publicKey);
  return data.publicKey;
}

async function getSharedKey(username) {
  if (state.sharedKeyCache.has(username)) return state.sharedKeyCache.get(username);
  const theirJwk = await fetchPublicKey(username);
  const theirKey = await importPublicKey(theirJwk);
  const shared = await deriveSharedKey(state.myPrivateKey, theirKey);
  state.sharedKeyCache.set(username, shared);
  return shared;
}

// ---------------- conversation view ----------------
function openConversation(conv) {
  state.activeConv = conv;
  const key = convKey(conv);
  delete state.unread[key];
  persistUnread();
  fingerprintPanel.hidden = true;
  appScreen.classList.add('show-conversation');
  renderConversationList();
  renderConversation();
  composerInput.focus();
}

backToContactsBtn.addEventListener('click', () => {
  appScreen.classList.remove('show-conversation');
});

function appendHistory(key, entry) {
  const storageKey = keys.history(state.username, key);
  const history = store.get(storageKey, []);
  history.push(entry);
  store.set(storageKey, history);
}

function renderConversation() {
  if (!state.activeConv) {
    conversationEmpty.hidden = false;
    conversationActive.hidden = true;
    return;
  }
  conversationEmpty.hidden = true;
  conversationActive.hidden = false;

  const conv = state.activeConv;
  const key = convKey(conv);
  const isGroup = conv.type === 'group';

  contactNameEl.textContent = isGroup ? conv.name : conv.id;
  groupMetaEl.hidden = !isGroup;
  if (isGroup) groupMetaEl.textContent = `${conv.members.length} members — ${conv.members.join(', ')}`;
  addMemberBtn.hidden = !isGroup;
  showFingerprintBtn.textContent = isGroup ? 'Safety codes' : 'Verify safety code';

  const history = store.get(keys.history(state.username, key), []);
  messageLogEl.innerHTML = '';
  for (const entry of history) {
    const div = document.createElement('div');
    div.className = 'message ' + (entry.from === state.username ? 'mine' : 'theirs');

    if (isGroup && entry.from !== state.username && entry.from !== 'system') {
      const sender = document.createElement('span');
      sender.className = 'sender';
      sender.textContent = entry.from;
      div.append(sender);
    }

    const text = document.createElement('span');
    text.className = 'text';
    text.textContent = entry.text;
    div.append(text);

    const meta = document.createElement('span');
    meta.className = 'meta';
    meta.textContent = new Date(entry.ts).toLocaleString();
    div.append(meta);

    messageLogEl.append(div);
  }
  messageLogEl.scrollTop = messageLogEl.scrollHeight;
}

showFingerprintBtn.addEventListener('click', async () => {
  if (!state.activeConv) return;
  if (!fingerprintPanel.hidden) { fingerprintPanel.hidden = true; return; }

  if (state.activeConv.type === 'group') {
    fingerprintContactName.textContent = state.activeConv.name;
    fingerprintValue.hidden = true;
    fingerprintList.hidden = false;
    fingerprintList.innerHTML = '';
    for (const member of state.activeConv.members) {
      if (member === state.username) continue;
      const row = document.createElement('div');
      row.className = 'fingerprint-row';
      const label = document.createElement('strong');
      label.textContent = member;
      const val = document.createElement('pre');
      val.className = 'fingerprint-value';
      try {
        const theirJwk = await fetchPublicKey(member);
        val.textContent = await safetyCode(state.myPublicJwk, theirJwk);
      } catch (err) {
        val.textContent = `(couldn't look up: ${err.message})`;
      }
      row.append(label, val);
      fingerprintList.append(row);
    }
  } else {
    fingerprintList.hidden = true;
    fingerprintValue.hidden = false;
    const theirJwk = await fetchPublicKey(state.activeConv.id);
    fingerprintContactName.textContent = state.activeConv.id;
    fingerprintValue.textContent = await safetyCode(state.myPublicJwk, theirJwk);
  }
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
  if (!text || !state.activeConv) return;
  const conv = state.activeConv;
  const key = convKey(conv);
  composerInput.value = '';
  composerInput.style.height = 'auto';
  try {
    if (conv.type === 'group') {
      // Fan-out: encrypt the same plaintext once per other member, using
      // the pairwise key we already have with each of them.
      const recipients = conv.members.filter((m) => m !== state.username);
      const messages = [];
      for (const member of recipients) {
        const sharedKey = await getSharedKey(member);
        const { ciphertext, iv } = await encryptText(sharedKey, text);
        messages.push({ to: member, ciphertext, iv });
      }
      await api('/api/send', { method: 'POST', body: { groupId: conv.id, messages } });
    } else {
      const sharedKey = await getSharedKey(conv.id);
      const { ciphertext, iv } = await encryptText(sharedKey, text);
      await api('/api/send', { method: 'POST', body: { to: conv.id, ciphertext, iv } });
    }
    appendHistory(key, { from: state.username, text, ts: Date.now() });
    renderConversationList();
    if (state.activeConv && convKey(state.activeConv) === key) renderConversation();
  } catch (err) {
    appendHistory(key, { from: 'system', text: `Not sent: ${err.message}`, ts: Date.now() });
    if (state.activeConv && convKey(state.activeConv) === key) renderConversation();
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
  // Group metadata notifications (not encrypted — the server already knows
  // group membership, since it has to validate it to route messages).
  if (msg.system === 'group-invite' || msg.system === 'group-update') {
    handleGroupSystemMessage(msg);
    return;
  }

  const { from, ciphertext, iv, ts, groupId } = msg;
  try {
    const sharedKey = await getSharedKey(from);
    const text = await decryptText(sharedKey, ciphertext, iv);

    if (groupId) {
      let conv = state.conversations.find((c) => c.type === 'group' && c.id === groupId);
      if (!conv) {
        // We don't know this group locally yet (its invite may not have
        // arrived, or arrived out of order) — fetch it before rendering.
        try {
          const { group } = await api(`/api/groups/${encodeURIComponent(groupId)}`);
          addConversation('group', group.id, { name: group.name, members: group.members });
          conv = state.conversations.find((c) => c.type === 'group' && c.id === groupId);
        } catch (err) {
          console.error('Could not resolve group', groupId, err);
          return;
        }
      }
      const key = convKey(conv);
      appendHistory(key, { from, text, ts, groupId });
      markUnreadIfInactive(key);
      renderConversationList();
      if (state.activeConv && convKey(state.activeConv) === key) renderConversation();
    } else {
      addConversation('dm', from);
      appendHistory(from, { from, text, ts });
      markUnreadIfInactive(from);
      renderConversationList();
      if (state.activeConv && convKey(state.activeConv) === from) renderConversation();
    }
  } catch (err) {
    console.error('Failed to decrypt message from', from, err);
  }
}

function handleGroupSystemMessage(msg) {
  const group = msg.group;
  if (!group) return;
  const existed = state.conversations.some((c) => c.type === 'group' && c.id === group.id);
  applyGroupUpdate(group);
  const key = `group:${group.id}`;
  if (!existed) {
    appendHistory(key, { from: 'system', text: `You were added to "${group.name}".`, ts: msg.ts || Date.now() });
    markUnreadIfInactive(key);
  }
  renderConversationList();
  if (state.activeConv && convKey(state.activeConv) === key) renderConversation();
}

function markUnreadIfInactive(key) {
  if (!(state.activeConv && convKey(state.activeConv) === key)) {
    state.unread[key] = true;
    persistUnread();
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
  for (const conv of state.conversations) store.remove(keys.history(username, convKey(conv)));
  store.remove(keys.conversations(username));
  store.remove(keys.contacts(username));
  store.remove(keys.unread(username));
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
