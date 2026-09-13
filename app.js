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
 *  - Photo/video attachments extend this model rather than replace it: the
 *    file is encrypted once with a random one-time key and uploaded as an
 *    anonymous ciphertext blob, and that one-time key is what actually gets
 *    sent as the "message" (via the pairwise key, exactly like text) to
 *    each recipient. The server stores a blob it can't open and never
 *    learns the file's name or content — only its size, the same way it
 *    already learns message timing.
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
 *  - Attachments are kept on the server indefinitely once uploaded — there
 *    is no expiry or "delete after delivery" job (unlike the message
 *    mailbox, which is popped on poll). Fine for a personal deploy; a
 *    production version would want a retention window.
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
// A one-time symmetric key used to encrypt a single attachment's bytes.
// Kept separate from the pairwise ECDH-derived key so a big file only ever
// needs to be encrypted/uploaded once, even when it's headed to a group —
// the small key itself is what gets wrapped per-recipient (see encryptText).
function generateContentKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function exportRawKey(key) {
  return bufToBase64(await crypto.subtle.exportKey('raw', key));
}
function importRawKey(b64) {
  return crypto.subtle.importKey('raw', base64ToBuf(b64), { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}
async function encryptBytes(key, arrayBuffer) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, arrayBuffer);
  return { ciphertext, iv: bufToBase64(iv) };
}
function decryptBytes(key, ciphertextBuf, ivB64) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(base64ToBuf(ivB64)) }, key, ciphertextBuf);
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
  set(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch (err) {
      // Storage can be blocked entirely (privacy settings, full disk, some
      // in-app browsers) rather than just non-persistent, in which case a
      // write throws synchronously instead of silently vanishing later.
      // Surface it immediately rather than losing the write with no trace.
      console.error('Local storage write failed for', key, err);
      showStorageWarning();
    }
  },
  remove(key) { localStorage.removeItem(key); },
};

// ---------------- storage persistence check ----------------
// This only catches localStorage being blocked/unavailable outright (write
// throws synchronously) — e.g. cookies/site data disabled in browser
// settings, some hardened browser configs, storage quota exhausted. It
// deliberately can't detect "works fine all session, then gets wiped when
// the browser closes" (the private/incognito browsing case): that succeeds
// silently on every write, and only ever shows up on the *next* visit, by
// which point the page reporting it would itself be a fresh, empty state
// indistinguishable from a genuine first-ever visit. There's no reliable
// way to tell those apart from inside the page, so that case isn't guessed
// at here — it's called out in-conversation instead.
function showStorageWarning() {
  if (storageWarning) storageWarning.hidden = false;
}
// The actual check runs further down, once the storage-warning DOM refs
// below have been assigned (see "storage persistence check, cont.").

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

// ---------------- disappearing messages ----------------
// A conversation (DM or group) can carry a `disappearing` field, one of:
//   'off'      - never (default)
//   'on-close' - wiped from this browser once you leave/close the chat
//   '24h'      - messages older than 24h are pruned
//   '7d'       - messages older than 7 days are pruned
// For a DM this is a personal, local-only display preference — each side
// can set their own, and the server never sees it. For a group it's a
// shared setting the server stores on the group record and only the
// creator can change (see POST /api/groups/:id/disappearing); this is
// enforced in renderDisappearingPanel below, not just decoration.
const DISAPPEARING_LABELS = { off: 'Off', 'on-close': 'On close', '24h': '24 hours', '7d': '7 days' };
const DISAPPEARING_MS = { '24h': 24 * 60 * 60 * 1000, '7d': 7 * 24 * 60 * 60 * 1000 };

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
  mediaObjectUrlCache: new Map(), // mediaId -> decrypted blob: object URL (in-memory only, this session)
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

// Attachments are already ciphertext, so they're transferred as raw bytes
// rather than base64-in-JSON (keep in sync with server.js MEDIA_MAX_BYTES).
const MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;

async function uploadMediaBlob(ciphertextBuf) {
  const res = await fetch(API_BASE + '/api/media', {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream', Authorization: `Bearer ${state.token}` },
    body: ciphertextBuf,
  });
  if (res.status === 401) {
    handleSessionExpired();
    throw new Error('session expired');
  }
  if (!res.ok) {
    let message = `upload failed (${res.status})`;
    try { const data = await res.json(); if (data.error) message = data.error; } catch { /* ignore */ }
    throw new Error(message);
  }
  const data = await res.json();
  return data.mediaId;
}

async function downloadMediaBlob(mediaId) {
  const res = await fetch(API_BASE + `/api/media/${encodeURIComponent(mediaId)}`, {
    headers: { Authorization: `Bearer ${state.token}` },
  });
  if (res.status === 401) {
    handleSessionExpired();
    throw new Error('session expired');
  }
  if (!res.ok) throw new Error(`couldn't fetch attachment (${res.status})`);
  return res.arrayBuffer();
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
const composerError = $('composer-error');
const attachmentPreview = $('attachment-preview');
const attachmentPreviewName = $('attachment-preview-name');
const attachmentRemoveBtn = $('attachment-remove-btn');
const composer = $('composer');
const attachmentInput = $('attachment-input');
const attachBtn = $('attach-btn');
const composerInput = $('composer-input');
const composerSubmitBtn = $('composer-submit');
const logoutBtn = $('logout-btn');
const forgetDeviceBtn = $('forget-device-btn');
const exportBackupBtn = $('export-backup-btn');
const importBackupBtn = $('import-backup-btn');
const importBackupInput = $('import-backup-input');
const storageWarning = $('storage-warning');
const storageWarningDismiss = $('storage-warning-dismiss');

// ---------------- storage persistence check, cont. ----------------
storageWarningDismiss.addEventListener('click', () => { storageWarning.hidden = true; });
(function checkStorageWritable() {
  try {
    const probeKey = 'relay:storage-probe';
    localStorage.setItem(probeKey, '1');
    localStorage.removeItem(probeKey);
  } catch (err) {
    console.error('localStorage is unavailable:', err);
    showStorageWarning();
  }
})();
const showFingerprintBtn = $('show-fingerprint-btn');
const backToContactsBtn = $('back-to-contacts-btn');
const fingerprintPanel = $('fingerprint-panel');
const fingerprintValue = $('fingerprint-value');
const fingerprintList = $('fingerprint-list');
const fingerprintContactName = $('fingerprint-contact-name');
const disappearingBtn = $('disappearing-btn');
const disappearingPanel = $('disappearing-panel');
const disappearingIntro = $('disappearing-intro');
const disappearingOptions = $('disappearing-options');

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

  // See resyncFromServer() above for why this is needed even though
  // conversations are also kept in localStorage.
  await resyncFromServer();

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

// Pulls the fields we mirror locally off a server-side group record. Kept
// in one place since name/members/owner/disappearing all need to travel
// together every time a group record arrives from the server (creation,
// invites, member adds, resync, disappearing changes, ...).
function groupFields(group) {
  return { name: group.name, members: group.members, owner: group.owner, disappearing: group.disappearing || 'off' };
}

// Adds a new conversation, or merges fresh fields (name/members) into an
// existing one — used both when the user starts a chat and when server
// notifications update a group's roster. Returns whether it was new.
//
// `notifyServer` (default true) controls whether a brand-new DM contact
// gets persisted server-side via syncContactToServer — see that function
// and resyncFromServer() below. It's turned off when we're the ones
// applying data that already came FROM the server, so we don't just echo
// it straight back.
function addConversation(type, id, extra = {}, { notifyServer = true } = {}) {
  const key = type === 'group' ? `group:${id}` : id;
  const idx = state.conversations.findIndex((c) => convKey(c) === key);
  const isNew = idx === -1;
  if (isNew) {
    state.conversations.unshift({ type, id, ...extra });
  } else {
    state.conversations[idx] = { ...state.conversations[idx], ...extra };
  }
  persistConversations();
  if (isNew && type === 'dm' && notifyServer) {
    syncContactToServer(id);
  }
  return isNew;
}

// Persists a DM contact server-side, mirroring how group membership is
// already persisted in db.groups — purely so it can be resynced later (see
// resyncFromServer). Fire-and-forget: this never blocks the UI, and if it
// fails, the only consequence is that this one contact won't reappear on
// another device or after this browser's storage is cleared, which is no
// worse than today's behavior.
function syncContactToServer(username) {
  api('/api/contacts', { method: 'POST', body: { username } }).catch((err) => {
    console.error('Could not sync contact to server:', err);
  });
}

// Pulls in anything the server already knows that this browser might not —
// groups you've been added to, and DM contacts you've started elsewhere.
// This matters because:
//  - a group-invite notification is only ever delivered once (the mailbox
//    is popped on poll), so if this browser wasn't around to see it, it's
//    otherwise gone for good even though the server still knows you're a
//    member — GET /api/groups exists exactly to resync that.
//  - contacts/groups otherwise live only in this browser's localStorage,
//    so a fresh browser, a different device, or storage getting cleared
//    would normally show an empty contact list even though your account
//    (and, for groups, your membership) still exists.
// Message *content* still never resyncs this way — that's unrelated to
// this fix and stays scoped to the browser that decrypted it, per the
// "No multi-device sync" limitation above.
async function resyncFromServer() {
  const [groupsResult, contactsResult] = await Promise.allSettled([
    api('/api/groups'),
    api('/api/contacts'),
  ]);
  if (groupsResult.status === 'fulfilled') {
    for (const g of groupsResult.value.groups) {
      addConversation('group', g.id, groupFields(g), { notifyServer: false });
    }
  } else {
    console.error('Could not resync groups from server:', groupsResult.reason);
  }
  if (contactsResult.status === 'fulfilled') {
    for (const c of contactsResult.value.contacts) {
      addConversation('dm', c, {}, { notifyServer: false });
    }
  } else {
    console.error('Could not resync contacts from server:', contactsResult.reason);
  }
}

function mediaLabel(media) {
  return (media.mimeType || '').startsWith('video') ? '🎥 Video' : '📷 Photo';
}

function lastPreview(key) {
  const history = store.get(keys.history(state.username, key), []);
  if (!history.length) return '';
  const last = history[history.length - 1];
  const prefix = last.from === state.username ? 'You: ' : (isGroupKey(key) && last.from !== 'system' ? `${last.from}: ` : '');
  const body = last.text || (last.media ? mediaLabel(last.media) : '');
  return prefix + body;
}

function renderConversationList() {
  pruneAllDisappearing();
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
    addConversation('group', group.id, groupFields(group));
    groupNameInput.value = '';
    pendingGroupMembers = [];
    renderMemberChips();
    renderConversationList();
    setNewConvoMode('dm');
    openConversation({ type: 'group', id: group.id, ...groupFields(group) });
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
  addConversation('group', group.id, groupFields(group));
  if (state.activeConv && state.activeConv.type === 'group' && state.activeConv.id === group.id) {
    state.activeConv = { type: 'group', id: group.id, ...groupFields(group) };
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

// ---------------- attachment rendering ----------------
// Fetches + decrypts an attachment on demand and caches the resulting blob
// URL in memory for the session, so re-rendering the conversation (which
// happens on every poll/send) doesn't re-download or re-decrypt it.
async function loadAndDecryptMedia(media) {
  const cached = state.mediaObjectUrlCache.get(media.mediaId);
  if (cached) return cached;
  const contentKey = await importRawKey(media.contentKey);
  const ciphertextBuf = await downloadMediaBlob(media.mediaId);
  const plainBuf = await decryptBytes(contentKey, ciphertextBuf, media.mediaIv);
  const url = URL.createObjectURL(new Blob([plainBuf], { type: media.mimeType || 'application/octet-stream' }));
  state.mediaObjectUrlCache.set(media.mediaId, url);
  return url;
}

function renderMediaElement(media) {
  const wrap = document.createElement('div');
  wrap.className = 'attachment';

  const isVideo = (media.mimeType || '').startsWith('video');
  const el = document.createElement(isVideo ? 'video' : 'img');
  el.className = 'attachment-media';
  if (isVideo) {
    el.controls = true;
    el.playsInline = true;
  } else {
    el.alt = media.name || 'attachment';
  }
  wrap.append(el);

  const status = document.createElement('p');
  status.className = 'attachment-status';
  status.textContent = 'Loading attachment…';
  wrap.append(status);

  const download = document.createElement('a');
  download.className = 'attachment-download';
  download.textContent = 'Save';
  download.download = media.name || 'attachment';
  download.hidden = true;
  wrap.append(download);

  const cachedUrl = state.mediaObjectUrlCache.get(media.mediaId);
  const applyUrl = (url) => {
    el.src = url;
    download.href = url;
    download.hidden = false;
    status.remove();
  };
  if (cachedUrl) {
    applyUrl(cachedUrl);
  } else {
    loadAndDecryptMedia(media).then(applyUrl).catch((err) => {
      status.textContent = `Couldn't load attachment: ${err.message}`;
      el.remove();
    });
  }
  return wrap;
}

// ---------------- conversation view ----------------
function openConversation(conv) {
  if (state.activeConv && convKey(state.activeConv) !== convKey(conv)) {
    closeConversationIfDisappearing(state.activeConv);
  }
  state.activeConv = conv;
  const key = convKey(conv);
  delete state.unread[key];
  persistUnread();
  fingerprintPanel.hidden = true;
  disappearingPanel.hidden = true;
  appScreen.classList.add('show-conversation');
  renderConversationList();
  renderConversation();
  composerInput.focus();
}

backToContactsBtn.addEventListener('click', () => {
  closeConversationIfDisappearing(state.activeConv);
  state.activeConv = null;
  appScreen.classList.remove('show-conversation');
  renderConversationList();
});

function appendHistory(key, entry) {
  const storageKey = keys.history(state.username, key);
  const history = store.get(storageKey, []);
  history.push(entry);
  store.set(storageKey, history);
}

// Removes messages that have aged out under a conversation's disappearing
// setting. 'on-close' is handled separately in closeConversationIfDisappearing,
// when the chat is actually left — this only covers the age-based modes.
// Each side prunes independently; it's a local display decision, not a
// delete request sent to anyone else. Returns whether anything was removed.
function pruneDisappearing(key) {
  const conv = state.conversations.find((c) => convKey(c) === key);
  const maxAge = conv && DISAPPEARING_MS[conv.disappearing];
  if (!maxAge) return false;
  const storageKey = keys.history(state.username, key);
  const history = store.get(storageKey, []);
  const cutoff = Date.now() - maxAge;
  const kept = history.filter((entry) => entry.ts >= cutoff);
  if (kept.length === history.length) return false;
  store.set(storageKey, kept);
  return true;
}

function pruneAllDisappearing() {
  let changed = false;
  for (const conv of state.conversations) {
    if (pruneDisappearing(convKey(conv))) changed = true;
  }
  return changed;
}

// Wipes a chat's message history entirely once it's actually left, if its
// mode is 'on-close'. Called wherever a conversation stops being the open
// one: switching to a different chat, going back to the contact list, and
// (via the beforeunload listener further down) closing the tab itself.
function closeConversationIfDisappearing(conv) {
  if (!conv || (conv.disappearing || 'off') !== 'on-close') return;
  store.remove(keys.history(state.username, convKey(conv)));
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
  pruneDisappearing(key);

  contactNameEl.textContent = isGroup ? conv.name : conv.id;
  groupMetaEl.hidden = !isGroup;
  if (isGroup) groupMetaEl.textContent = `${conv.members.length} members — ${conv.members.join(', ')}`;
  addMemberBtn.hidden = !isGroup;
  showFingerprintBtn.textContent = isGroup ? 'Safety codes' : 'Verify safety code';
  disappearingBtn.textContent = `Disappearing: ${DISAPPEARING_LABELS[conv.disappearing || 'off']}`;

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

    if (entry.media) {
      div.append(renderMediaElement(entry.media));
    }

    if (entry.text) {
      const text = document.createElement('span');
      text.className = 'text';
      text.textContent = entry.text;
      div.append(text);
    }

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
  disappearingPanel.hidden = true;
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

disappearingBtn.addEventListener('click', () => {
  if (!state.activeConv) return;
  fingerprintPanel.hidden = true;
  if (!disappearingPanel.hidden) { disappearingPanel.hidden = true; return; }
  renderDisappearingPanel();
  disappearingPanel.hidden = false;
});

function renderDisappearingPanel() {
  const conv = state.activeConv;
  if (!conv) return;
  const isGroup = conv.type === 'group';
  const canEdit = !isGroup || conv.owner === state.username;
  const current = conv.disappearing || 'off';

  disappearingIntro.textContent = isGroup
    ? (canEdit
        ? "Choose how long messages stick around for everyone in this group."
        : `Set by the group's creator (${conv.owner}) — only they can change it.`)
    : "Choose how long messages stick around in this chat, just for you. It doesn't affect the other side's copy.";

  disappearingOptions.innerHTML = '';
  for (const mode of ['off', 'on-close', '24h', '7d']) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'mode-tab' + (mode === current ? ' active' : '');
    btn.textContent = DISAPPEARING_LABELS[mode];
    if (canEdit) {
      btn.addEventListener('click', () => selectDisappearing(mode));
    } else {
      btn.disabled = true;
    }
    disappearingOptions.append(btn);
  }
}

async function selectDisappearing(mode) {
  const conv = state.activeConv;
  if (!conv) return;
  if (conv.type === 'group') {
    if (conv.owner !== state.username) return;
    const buttons = [...disappearingOptions.querySelectorAll('button')];
    buttons.forEach((b) => { b.disabled = true; });
    try {
      const { group } = await api(`/api/groups/${encodeURIComponent(conv.id)}/disappearing`, {
        method: 'POST',
        body: { mode },
      });
      applyGroupUpdate(group);
      renderDisappearingPanel();
    } catch (err) {
      alert(err.message);
      buttons.forEach((b) => { b.disabled = false; });
      return;
    }
  } else {
    addConversation('dm', conv.id, { disappearing: mode }, { notifyServer: false });
    state.activeConv = { ...conv, disappearing: mode };
    renderDisappearingPanel();
  }
  pruneDisappearing(convKey(state.activeConv));
  renderConversation();
  renderConversationList();
}

// ---------------- attachment picking ----------------
let pendingAttachment = null; // { file } — cleared once sent or removed

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

attachBtn.addEventListener('click', () => attachmentInput.click());

attachmentInput.addEventListener('change', () => {
  composerError.hidden = true;
  const file = attachmentInput.files && attachmentInput.files[0];
  attachmentInput.value = ''; // allow picking the same file again later
  if (!file) return;
  if (!/^image\/|^video\//.test(file.type)) {
    composerError.textContent = 'Only images and videos can be attached.';
    composerError.hidden = false;
    return;
  }
  if (file.size > MAX_ATTACHMENT_BYTES) {
    composerError.textContent = `That file is too big — attachments are limited to ${Math.floor(MAX_ATTACHMENT_BYTES / (1024 * 1024))}MB.`;
    composerError.hidden = false;
    return;
  }
  pendingAttachment = { file };
  attachmentPreviewName.textContent = `${file.name} (${formatBytes(file.size)})`;
  attachmentPreview.hidden = false;
});

attachmentRemoveBtn.addEventListener('click', () => {
  pendingAttachment = null;
  attachmentPreview.hidden = true;
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

// Builds the string that actually gets encrypted+sent as a "message". Plain
// text messages are unchanged (still just the raw string, for backward
// compatibility). A message carrying an attachment is instead a small JSON
// envelope: the attachment's own bytes never travel through /api/send at
// all, only a reference to the already-uploaded blob plus the one-time key
// needed to open it.
function buildOutgoingPayload(text, media) {
  if (!media) return text;
  return JSON.stringify({ v: 1, kind: 'media', ...media, caption: text || undefined });
}

composer.addEventListener('submit', async (e) => {
  e.preventDefault();
  const text = composerInput.value.trim();
  const attachment = pendingAttachment;
  if (!state.activeConv || (!text && !attachment)) return;
  const conv = state.activeConv;
  const key = convKey(conv);

  composerInput.value = '';
  composerInput.style.height = 'auto';
  pendingAttachment = null;
  attachmentPreview.hidden = true;
  composerError.hidden = true;

  const originalLabel = composerSubmitBtn.textContent;
  composerSubmitBtn.disabled = true;
  attachBtn.disabled = true;

  try {
    let media = null; // the small, sendable reference: { mediaId, mediaIv, mimeType, size, name, contentKey }
    let fileBuf = null; // the plaintext bytes, kept only long enough to cache our own sent copy locally

    if (attachment) {
      composerSubmitBtn.textContent = 'Encrypting…';
      fileBuf = await attachment.file.arrayBuffer();
      const contentKey = await generateContentKey();
      const { ciphertext: mediaCiphertext, iv: mediaIv } = await encryptBytes(contentKey, fileBuf);

      composerSubmitBtn.textContent = 'Uploading…';
      const mediaId = await uploadMediaBlob(mediaCiphertext);

      media = {
        mediaId,
        mediaIv,
        mimeType: attachment.file.type || 'application/octet-stream',
        size: attachment.file.size,
        name: attachment.file.name,
        contentKey: await exportRawKey(contentKey),
      };
    }

    composerSubmitBtn.textContent = 'Sending…';
    const payload = buildOutgoingPayload(text, media);

    if (conv.type === 'group') {
      // Fan-out: encrypt the same payload once per other member, using the
      // pairwise key we already have with each of them. For an attachment,
      // the (large) file itself was uploaded exactly once above — this
      // loop only re-wraps the small one-time content key per recipient.
      const recipients = conv.members.filter((m) => m !== state.username);
      const messages = [];
      for (const member of recipients) {
        const sharedKey = await getSharedKey(member);
        const { ciphertext, iv } = await encryptText(sharedKey, payload);
        messages.push({ to: member, ciphertext, iv });
      }
      await api('/api/send', { method: 'POST', body: { groupId: conv.id, messages } });
    } else {
      const sharedKey = await getSharedKey(conv.id);
      const { ciphertext, iv } = await encryptText(sharedKey, payload);
      await api('/api/send', { method: 'POST', body: { to: conv.id, ciphertext, iv } });
    }

    const entry = { from: state.username, ts: Date.now() };
    if (text) entry.text = text;
    if (media) {
      entry.media = media;
      // We already have the plaintext bytes locally — cache them straight
      // away so our own sent message renders instantly, no round trip.
      state.mediaObjectUrlCache.set(media.mediaId, URL.createObjectURL(new Blob([fileBuf], { type: media.mimeType })));
    }
    appendHistory(key, entry);
    renderConversationList();
    if (state.activeConv && convKey(state.activeConv) === key) renderConversation();
  } catch (err) {
    appendHistory(key, { from: 'system', text: `Not sent: ${err.message}`, ts: Date.now() });
    if (state.activeConv && convKey(state.activeConv) === key) renderConversation();
  } finally {
    composerSubmitBtn.disabled = false;
    attachBtn.disabled = false;
    composerSubmitBtn.textContent = originalLabel;
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
    // Age-based disappearing needs to happen even when nothing new arrives
    // this tick. Only re-render what actually changed, so an idle chat
    // doesn't get its message log silently rebuilt (and scrolled to the
    // bottom) every few seconds for no reason.
    const activeKey = state.activeConv ? convKey(state.activeConv) : null;
    const activeChanged = activeKey ? pruneDisappearing(activeKey) : false;
    const otherChanged = state.conversations
      .filter((c) => convKey(c) !== activeKey)
      .some((c) => pruneDisappearing(convKey(c)));
    if (activeChanged || otherChanged) renderConversationList();
    if (activeChanged) renderConversation();
    await sleep(3000);
  }
  state.polling = false;
}
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// Distinguishes a plain-text message from an attachment envelope. Attachment
// messages are sent as a small JSON payload (see buildOutgoingPayload)
// instead of raw text; anything that doesn't match that exact shape is
// treated as plain text, same as before attachments existed.
function parseIncomingPayload(decrypted) {
  let parsed = null;
  try { parsed = JSON.parse(decrypted); } catch { /* not JSON -> plain text */ }
  if (parsed && parsed.v === 1 && parsed.kind === 'media' && parsed.mediaId && parsed.mediaIv && parsed.contentKey) {
    const entry = {
      media: {
        mediaId: parsed.mediaId,
        mediaIv: parsed.mediaIv,
        mimeType: parsed.mimeType,
        size: parsed.size,
        name: parsed.name,
        contentKey: parsed.contentKey,
      },
    };
    if (parsed.caption) entry.text = parsed.caption;
    return entry;
  }
  return { text: decrypted };
}

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
    const decrypted = await decryptText(sharedKey, ciphertext, iv);
    const entry = { from, ts, ...parseIncomingPayload(decrypted) };
    if (groupId) entry.groupId = groupId;

    if (groupId) {
      let conv = state.conversations.find((c) => c.type === 'group' && c.id === groupId);
      if (!conv) {
        // We don't know this group locally yet (its invite may not have
        // arrived, or arrived out of order) — fetch it before rendering.
        try {
          const { group } = await api(`/api/groups/${encodeURIComponent(groupId)}`);
          addConversation('group', group.id, groupFields(group));
          conv = state.conversations.find((c) => c.type === 'group' && c.id === groupId);
        } catch (err) {
          console.error('Could not resolve group', groupId, err);
          return;
        }
      }
      const key = convKey(conv);
      appendHistory(key, entry);
      markUnreadIfInactive(key);
      renderConversationList();
      if (state.activeConv && convKey(state.activeConv) === key) renderConversation();
    } else {
      addConversation('dm', from);
      appendHistory(from, entry);
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
  closeConversationIfDisappearing(state.activeConv);
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

// ---------------- backup export / import ----------------
// Contacts (conversations), history, and the encryption identity all live
// only in this browser's localStorage by design (see the header comment
// on "No multi-device sync"). That means anything that clears site data —
// a private/incognito window closing, a browser's "clear on exit" setting,
// switching browsers or devices, reinstalling — loses them for good with
// no server copy to fall back on. This is the escape hatch: a manual,
// user-held backup of exactly that local state.
function buildBackup(username) {
  const identity = store.get(keys.identity(username));
  const conversations = store.get(keys.conversations(username), []);
  const unread = store.get(keys.unread(username), {});
  const history = {};
  for (const conv of conversations) {
    const key = convKey(conv);
    history[key] = store.get(keys.history(username, key), []);
  }
  return { relayBackupVersion: 1, username, exportedAt: new Date().toISOString(), identity, conversations, unread, history };
}

exportBackupBtn.addEventListener('click', () => {
  if (!state.username) return;
  const backup = buildBackup(state.username);
  const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `relay-backup-${state.username}-${Date.now()}.json`;
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
});

importBackupBtn.addEventListener('click', () => importBackupInput.click());

importBackupInput.addEventListener('change', async () => {
  const file = importBackupInput.files && importBackupInput.files[0];
  importBackupInput.value = '';
  if (!file) return;
  try {
    const backup = JSON.parse(await file.text());
    if (!backup || backup.relayBackupVersion !== 1 || typeof backup.username !== 'string') {
      throw new Error("That doesn't look like a Relay backup file.");
    }
    if (backup.username !== state.username) {
      alert(`This backup is for the account "${backup.username}", but you're signed in as "${state.username}". Log in as "${backup.username}" first, then import.`);
      return;
    }
    const ok = confirm(
      `Import this backup? It will replace your current contacts and message history on this device with the ones from ${new Date(backup.exportedAt).toLocaleString()}.`
    );
    if (!ok) return;
    const username = backup.username;
    if (backup.identity) {
      store.set(keys.identity(username), backup.identity);
      // If this device had no identity before now, logging in already
      // generated and published a fresh one — republish the restored key
      // so the server (and everyone messaging you) agrees with what you
      // just imported, instead of silently breaking encryption.
      try {
        await api('/api/publickey', { method: 'POST', body: { publicKey: backup.identity.publicJwk } });
      } catch (err) {
        console.error('Could not re-publish restored public key:', err);
      }
    }
    store.set(keys.conversations(username), backup.conversations || []);
    store.set(keys.unread(username), backup.unread || {});
    for (const [histKey, hist] of Object.entries(backup.history || {})) {
      store.set(keys.history(username, histKey), hist);
    }
    location.reload();
  } catch (err) {
    alert(`Could not import backup: ${err.message}`);
  }
});

// Covers actually closing the tab/browser while an 'on-close' chat is
// open — the in-app navigation paths above (openConversation, the back
// button, logout) handle every other way of leaving a chat.
window.addEventListener('beforeunload', () => {
  closeConversationIfDisappearing(state.activeConv);
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
