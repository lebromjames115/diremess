'use strict';
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { transact } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://diremess.win,https://www.diremess.win')
  .split(',')
  .map((s) => s.trim());
const MAX_GROUP_MEMBERS = 50;
// Disappearing-messages modes a chat (DM or group) can be set to. The
// server only needs to know about this for groups — see the "disappearing"
// field on group objects below. For DMs it's a purely local, per-user
// display preference the client keeps to itself, so the server never sees
// it and this list is only consulted when validating the group endpoint.
const DISAPPEARING_MODES = ['off', 'on-close', '24h', '7d'];

// ---- media attachments (encrypted blob storage) ----
// Attachments follow the exact same "server only ever sees ciphertext" rule
// as message text — they don't introduce a new trust model, just a bigger
// payload:
//   1. The client generates a random one-time AES-256-GCM "content key" and
//      encrypts the raw file bytes with it. Only that ciphertext is
//      uploaded here, once — even for a group message, we never ask the
//      client to re-upload the same file once per recipient.
//   2. The content key is tiny, so it rides inside the normal per-recipient
//      encrypted message payload (the existing ciphertext/iv fields on
//      /api/send), wrapped with each recipient's usual pairwise key —
//      exactly like a text message. Only someone who can decrypt that
//      message ever learns the key needed to open the attachment.
// The server can see a blob's *size*, the same way it already sees message
// timing and (for groups) membership — but never its content, filename, or
// whether it's a photo or a video.
const MEDIA_DIR = path.join(__dirname, 'data', 'media');
const MEDIA_MAX_BYTES = 25 * 1024 * 1024; // 25MB ciphertext per attachment
const MEDIA_ID_RE = /^[0-9a-f-]{36}$/i;
// NOTE: uploaded attachments are kept indefinitely — there's no expiry or
// "delete after delivery" job, unlike the message mailbox (which is popped
// on poll). Fine for a personal deploy; a production version would want a
// retention window.
function ensureMediaDir() {
  if (!fs.existsSync(MEDIA_DIR)) fs.mkdirSync(MEDIA_DIR, { recursive: true });
}
ensureMediaDir();

if (!JWT_SECRET) {
  console.error('Missing JWT_SECRET environment variable. Set it before starting the server.');
  process.exit(1);
}

app.use(express.json());
app.use(cors({ origin: ALLOWED_ORIGINS }));

const USERNAME_RE = /^[a-zA-Z0-9_]{3,32}$/;

function signToken(username) {
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const [, token] = header.split(' ');
  if (!token) return res.status(401).json({ error: 'session expired' });
  try {
    req.username = jwt.verify(token, JWT_SECRET).username;
    next();
  } catch {
    return res.status(401).json({ error: 'session expired' });
  }
}

// ---- static frontend ----
// A production deploy can serve index.html/app.js/style.css from a static
// host instead (see the API_BASE comment in app.js) — but for a plain
// `node server.js`, this backend should still be able to serve its own
// front end. Deliberately an allow-list of exactly those three files
// rather than a blanket static-directory mount: this directory also holds
// server.js, db.js, .env, and data/db.json (password hashes, public
// keys) — none of which should ever be reachable over HTTP.
const PUBLIC_FILES = { '/': 'index.html', '/index.html': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css' };
const PUBLIC_CONTENT_TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };
function serveStaticFile(req, res) {
  const filename = PUBLIC_FILES[req.path];
  fs.readFile(path.join(__dirname, filename), (err, data) => {
    if (err) return res.status(404).json({ error: 'Not found.' });
    res.type(PUBLIC_CONTENT_TYPES[path.extname(filename)] || 'application/octet-stream');
    return res.send(data);
  });
}
app.get('/', serveStaticFile);
app.get('/index.html', serveStaticFile);
app.get('/app.js', serveStaticFile);
app.get('/style.css', serveStaticFile);

// ---- account creation ----
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) {
    return res.status(400).json({ error: 'Username must be 3-32 letters, numbers, or underscores.' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }
  try {
    const { conflict } = await transact(async (db) => {
      if (db.users[username]) return { conflict: true };
      const passwordHash = await bcrypt.hash(password, 10);
      db.users[username] = { passwordHash, publicKey: null };
      db.mailboxes[username] = [];
      return { conflict: false };
    });
    if (conflict) return res.status(409).json({ error: 'That username is taken.' });
    return res.json({ username, token: signToken(username) });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Registration failed.' });
  }
});

// ---- login ----
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  try {
    const { ok } = await transact(async (db) => {
      const user = db.users[username];
      if (!user) return { ok: false };
      return { ok: await bcrypt.compare(password, user.passwordHash) };
    });
    if (!ok) return res.status(401).json({ error: 'Invalid username or password.' });
    return res.json({ username, token: signToken(username) });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Login failed.' });
  }
});

// ---- public key upload/lookup ----
app.post('/api/publickey', auth, async (req, res) => {
  const { publicKey } = req.body || {};
  if (!publicKey) return res.status(400).json({ error: 'publicKey is required.' });
  await transact((db) => {
    if (db.users[req.username]) db.users[req.username].publicKey = publicKey;
  });
  return res.json({ ok: true });
});

app.get('/api/publickey/:username', async (req, res) => {
  const user = await transact((db) => db.users[req.params.username] || null);
  if (!user || !user.publicKey) return res.status(404).json({ error: 'User not found.' });
  return res.json({ publicKey: user.publicKey });
});

// ---- media attachments ----
// Uploads/downloads are raw bytes (Content-Type: application/octet-stream),
// not JSON — the payload is already ciphertext, so base64-in-JSON would
// just waste ~33% of the transfer for no benefit.
app.post('/api/media', auth, express.raw({ type: 'application/octet-stream', limit: MEDIA_MAX_BYTES }), (req, res) => {
  const buf = req.body;
  if (!Buffer.isBuffer(buf) || buf.length === 0) {
    return res.status(400).json({ error: 'Empty upload.' });
  }
  const id = crypto.randomUUID();
  try {
    ensureMediaDir();
    fs.writeFileSync(path.join(MEDIA_DIR, id), buf);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Could not store attachment.' });
  }
  return res.json({ mediaId: id });
});

app.get('/api/media/:id', auth, (req, res) => {
  if (!MEDIA_ID_RE.test(req.params.id)) return res.status(404).json({ error: 'Not found.' });
  fs.readFile(path.join(MEDIA_DIR, req.params.id), (err, data) => {
    if (err) return res.status(404).json({ error: 'Not found.' });
    res.type('application/octet-stream');
    return res.send(data);
  });
});

// ---- groups ----
// Note on the E2E model: message CONTENT is always end-to-end encrypted —
// a group message is just the same plaintext encrypted separately to each
// member with the existing pairwise ECDH keys (fan-out), so the server never
// gains the ability to read anything it couldn't already read in a 1:1 chat.
// Group *metadata* (name, member list) is necessarily visible to the server,
// since it has to validate membership to route messages — the same way it
// already knows who your contacts are from who you talk to.
app.post('/api/groups', auth, async (req, res) => {
  const { name, members } = req.body || {};
  const trimmedName = typeof name === 'string' ? name.trim() : '';
  if (!trimmedName || trimmedName.length > 80) {
    return res.status(400).json({ error: 'Group name must be 1-80 characters.' });
  }
  if (!Array.isArray(members) || members.length === 0) {
    return res.status(400).json({ error: 'Add at least one other member.' });
  }
  const uniqueMembers = Array.from(new Set(members.filter((m) => typeof m === 'string')));
  for (const m of uniqueMembers) {
    if (!USERNAME_RE.test(m)) return res.status(400).json({ error: `Invalid username: ${m}` });
  }
  const allMembers = Array.from(new Set([req.username, ...uniqueMembers]));
  if (allMembers.length > MAX_GROUP_MEMBERS) {
    return res.status(400).json({ error: `Groups are limited to ${MAX_GROUP_MEMBERS} members.` });
  }
  try {
    const { error, group } = await transact(async (db) => {
      for (const m of allMembers) {
        if (!db.users[m]) return { error: `No such user: ${m}` };
      }
      const id = crypto.randomUUID();
      const g = { id, name: trimmedName, owner: req.username, members: allMembers, disappearing: 'off', createdAt: Date.now() };
      db.groups[id] = g;
      for (const m of allMembers) {
        if (m === req.username) continue;
        db.mailboxes[m] = db.mailboxes[m] || [];
        db.mailboxes[m].push({ system: 'group-invite', group: g, ts: Date.now() });
      }
      return { group: g };
    });
    if (error) return res.status(400).json({ error });
    return res.json({ group });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Could not create group.' });
  }
});

// List groups the caller belongs to (useful to resync on a fresh device).
app.get('/api/groups', auth, async (req, res) => {
  const groups = await transact((db) => Object.values(db.groups).filter((g) => g.members.includes(req.username)));
  return res.json({ groups });
});

app.get('/api/groups/:id', auth, async (req, res) => {
  const group = await transact((db) => db.groups[req.params.id] || null);
  if (!group || !group.members.includes(req.username)) {
    return res.status(404).json({ error: 'Group not found.' });
  }
  return res.json({ group });
});

app.post('/api/groups/:id/members', auth, async (req, res) => {
  const { username } = req.body || {};
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) {
    return res.status(400).json({ error: 'A valid username is required.' });
  }
  try {
    const { error, group } = await transact(async (db) => {
      const g = db.groups[req.params.id];
      if (!g || !g.members.includes(req.username)) return { error: 'not-found' };
      if (!db.users[username]) return { error: `No such user: ${username}` };
      if (g.members.includes(username)) return { error: `${username} is already in the group.` };
      if (g.members.length >= MAX_GROUP_MEMBERS) return { error: `Groups are limited to ${MAX_GROUP_MEMBERS} members.` };
      g.members.push(username);
      // New member gets the full invite; existing members get an update so
      // their local member list (and future fan-out sends) stay in sync.
      db.mailboxes[username] = db.mailboxes[username] || [];
      db.mailboxes[username].push({ system: 'group-invite', group: g, ts: Date.now() });
      for (const m of g.members) {
        if (m === req.username || m === username) continue;
        db.mailboxes[m] = db.mailboxes[m] || [];
        db.mailboxes[m].push({ system: 'group-update', group: g, ts: Date.now() });
      }
      return { group: g };
    });
    if (error === 'not-found') return res.status(404).json({ error: 'Group not found.' });
    if (error) return res.status(400).json({ error });
    return res.json({ group });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Could not add member.' });
  }
});

// Only the creator can change this — it applies to every member's view of
// the group, unlike a DM's disappearing setting which is purely personal.
// Broadcast the same way an add-member update already is: a "group-update"
// mailbox notification to everyone else so their client picks it up next
// poll (see handleGroupSystemMessage / applyGroupUpdate in app.js).
app.post('/api/groups/:id/disappearing', auth, async (req, res) => {
  const { mode } = req.body || {};
  if (!DISAPPEARING_MODES.includes(mode)) {
    return res.status(400).json({ error: `mode must be one of: ${DISAPPEARING_MODES.join(', ')}` });
  }
  try {
    const { error, group } = await transact((db) => {
      const g = db.groups[req.params.id];
      if (!g || !g.members.includes(req.username)) return { error: 'not-found' };
      if (g.owner !== req.username) return { error: 'forbidden' };
      g.disappearing = mode;
      for (const m of g.members) {
        if (m === req.username) continue;
        db.mailboxes[m] = db.mailboxes[m] || [];
        db.mailboxes[m].push({ system: 'group-update', group: g, ts: Date.now() });
      }
      return { group: g };
    });
    if (error === 'not-found') return res.status(404).json({ error: 'Group not found.' });
    if (error === 'forbidden') return res.status(403).json({ error: 'Only the group creator can change this.' });
    if (error) return res.status(400).json({ error });
    return res.json({ group });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Could not update disappearing-messages setting.' });
  }
});

// ---- contacts ----
// A plain per-user list of usernames, purely so a DM conversation resyncs
// on a fresh browser or after this device's local storage is cleared —
// same idea, and the same privacy level, as the group membership list
// above ("db.groups[id].members"): the server already necessarily learns
// a "to" username on every /api/send call in order to route it, this just
// remembers it going forward instead of only for the life of one mailbox
// entry. It never reveals anything about message content or timing beyond
// what routing already exposes.
app.get('/api/contacts', auth, async (req, res) => {
  const contacts = await transact((db) => db.contacts[req.username] || []);
  return res.json({ contacts });
});

app.post('/api/contacts', auth, async (req, res) => {
  const { username } = req.body || {};
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) {
    return res.status(400).json({ error: 'A valid username is required.' });
  }
  if (username === req.username) {
    return res.status(400).json({ error: "That's you." });
  }
  try {
    const { error, contacts } = await transact((db) => {
      if (!db.users[username]) return { error: `No such user: ${username}` };
      db.contacts[req.username] = db.contacts[req.username] || [];
      if (!db.contacts[req.username].includes(username)) {
        db.contacts[req.username].push(username);
      }
      return { contacts: db.contacts[req.username] };
    });
    if (error) return res.status(400).json({ error });
    return res.json({ contacts });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Could not save contact.' });
  }
});

// ---- send / poll (ciphertext relay only) ----
app.post('/api/send', auth, async (req, res) => {
  const { to, ciphertext, iv, groupId, messages } = req.body || {};

  // Group send: the client has already encrypted the plaintext separately
  // for each member using the existing pairwise keys. We just validate
  // membership and fan the pre-encrypted copies out to each recipient's
  // mailbox — the server still never sees plaintext.
  if (groupId) {
    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'messages array is required for group sends.' });
    }
    for (const m of messages) {
      if (!m || typeof m.to !== 'string' || !m.ciphertext || !m.iv) {
        return res.status(400).json({ error: 'Each group message needs to, ciphertext, and iv.' });
      }
    }
    try {
      const { error } = await transact((db) => {
        const g = db.groups[groupId];
        if (!g || !g.members.includes(req.username)) return { error: 'not-found' };
        for (const m of messages) {
          if (!g.members.includes(m.to)) return { error: `${m.to} is not in this group.` };
        }
        const msgId = crypto.randomUUID();
        for (const m of messages) {
          db.mailboxes[m.to] = db.mailboxes[m.to] || [];
          db.mailboxes[m.to].push({ from: req.username, groupId, msgId, ciphertext: m.ciphertext, iv: m.iv, ts: Date.now() });
        }
        return { error: null };
      });
      if (error === 'not-found') return res.status(404).json({ error: 'Group not found.' });
      if (error) return res.status(400).json({ error });
      return res.json({ ok: true });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: 'Send failed.' });
    }
  }

  // Direct message.
  if (!to || !ciphertext || !iv) {
    return res.status(400).json({ error: 'to, ciphertext, and iv are required.' });
  }
  const { exists } = await transact((db) => {
    if (!db.users[to]) return { exists: false };
    db.mailboxes[to] = db.mailboxes[to] || [];
    db.mailboxes[to].push({ from: req.username, ciphertext, iv, ts: Date.now() });
    return { exists: true };
  });
  if (!exists) return res.status(404).json({ error: 'No such user.' });
  return res.json({ ok: true });
});

app.get('/api/poll', auth, async (req, res) => {
  const messages = await transact((db) => {
    const msgs = db.mailboxes[req.username] || [];
    db.mailboxes[req.username] = [];
    return msgs;
  });
  return res.json({ messages });
});

// Catches errors thrown by body-parsers (e.g. an attachment over
// MEDIA_MAX_BYTES) so callers always get JSON back instead of Express's
// default HTML error page.
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: `Attachments are limited to ${Math.floor(MEDIA_MAX_BYTES / (1024 * 1024))}MB.` });
  }
  console.error(err);
  return res.status(500).json({ error: 'Unexpected server error.' });
});

app.listen(PORT, () => console.log(`Relay server listening on port ${PORT}`));
