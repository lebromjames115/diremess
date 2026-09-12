'use strict';
require('dotenv').config();
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

// ---- send / poll (ciphertext relay only) ----
app.post('/api/send', auth, async (req, res) => {
  const { to, ciphertext, iv } = req.body || {};
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

app.listen(PORT, () => console.log(`Relay server listening on port ${PORT}`));
