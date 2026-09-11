'use strict';
/**
 * Relay — a minimal end-to-end-encrypted messaging server.
 *
 * This server NEVER sees plaintext messages or private keys. It only stores:
 *   - usernames + password hashes (for login)
 *   - each user's PUBLIC key (harmless to store in the open)
 *   - encrypted message blobs, queued until the recipient polls for them
 *
 * All encryption/decryption happens in the browser (see public/app.js).
 * Zero external dependencies — only Node.js core modules — so deployment
 * is just "install Node, run this file."
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

// ---------- tiny JSON persistence ----------
function loadJSON(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}
function saveJSON(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data), 'utf8');
}

// users: { [username]: { salt, hash, publicKey: jwk|null, createdAt } }
let users = loadJSON(USERS_FILE, {});
// messageQueue: { [recipientUsername]: [ { id, from, ciphertext, iv, ts } ] }
let messageQueue = loadJSON(MESSAGES_FILE, {});

// sessions: token -> username (in-memory only; a restart logs everyone out)
const sessions = new Map();
// long-poll waiters: username -> [ resolveFns ]
const waiters = new Map();

function persistUsers() { saveJSON(USERS_FILE, users); }
function persistMessages() { saveJSON(MESSAGES_FILE, messageQueue); }

// ---------- password hashing (Node's built-in scrypt, no dependency needed) ----------
function makeSalt() { return crypto.randomBytes(16).toString('hex'); }
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function timingSafeEqualHex(a, b) {
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}
function newToken() { return crypto.randomBytes(32).toString('hex'); }

const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/;

// ---------- request helpers ----------
function readBody(req, limit = 256 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('payload too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('invalid json'));
      }
    });
    req.on('error', reject);
  });
}

function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function authenticate(req) {
  const auth = req.headers['authorization'] || '';
  const m = /^Bearer (.+)$/.exec(auth);
  if (!m) return null;
  return sessions.get(m[1]) || null;
}

// ---------- static file serving ----------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function serveStatic(req, res, pathname) {
  let filePath = pathname === '/' ? '/index.html' : pathname;
  filePath = path.normalize(filePath).replace(/^(\.\.[/\\])+/, '');
  const fullPath = path.join(PUBLIC_DIR, filePath);
  if (!fullPath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }
  fs.readFile(fullPath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
      return;
    }
    const ext = path.extname(fullPath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// ---------- route handlers ----------
async function handleRegister(req, res) {
  let body;
  try { body = await readBody(req); } catch { return sendJSON(res, 400, { error: 'bad request' }); }
  const { username, password } = body;
  if (typeof username !== 'string' || typeof password !== 'string') {
    return sendJSON(res, 400, { error: 'username and password required' });
  }
  if (!USERNAME_RE.test(username)) {
    return sendJSON(res, 400, { error: 'username must be 3-32 chars: letters, numbers, _ . -' });
  }
  if (password.length < 8) {
    return sendJSON(res, 400, { error: 'password must be at least 8 characters' });
  }
  if (users[username]) {
    return sendJSON(res, 409, { error: 'username already taken' });
  }
  const salt = makeSalt();
  const hash = hashPassword(password, salt);
  users[username] = { salt, hash, publicKey: null, createdAt: Date.now() };
  persistUsers();
  const token = newToken();
  sessions.set(token, username);
  sendJSON(res, 200, { token, username });
}

async function handleLogin(req, res) {
  let body;
  try { body = await readBody(req); } catch { return sendJSON(res, 400, { error: 'bad request' }); }
  const { username, password } = body;
  const user = users[username];
  if (!user) return sendJSON(res, 401, { error: 'invalid username or password' });
  const hash = hashPassword(password, user.salt);
  if (!timingSafeEqualHex(hash, user.hash)) {
    return sendJSON(res, 401, { error: 'invalid username or password' });
  }
  const token = newToken();
  sessions.set(token, username);
  sendJSON(res, 200, { token, username, publicKey: user.publicKey });
}

async function handlePublicKeyUpload(req, res) {
  const username = authenticate(req);
  if (!username) return sendJSON(res, 401, { error: 'not authenticated' });
  let body;
  try { body = await readBody(req); } catch { return sendJSON(res, 400, { error: 'bad request' }); }
  if (!body.publicKey) return sendJSON(res, 400, { error: 'publicKey required' });
  users[username].publicKey = body.publicKey;
  persistUsers();
  sendJSON(res, 200, { ok: true });
}

function handlePublicKeyFetch(req, res, targetUsername) {
  const user = users[targetUsername];
  if (!user || !user.publicKey) {
    return sendJSON(res, 404, { error: 'user not found or has no key yet' });
  }
  sendJSON(res, 200, { username: targetUsername, publicKey: user.publicKey });
}

async function handleSend(req, res) {
  const username = authenticate(req);
  if (!username) return sendJSON(res, 401, { error: 'not authenticated' });
  let body;
  try { body = await readBody(req); } catch { return sendJSON(res, 400, { error: 'bad request' }); }
  const { to, ciphertext, iv } = body;
  if (typeof to !== 'string' || typeof ciphertext !== 'string' || typeof iv !== 'string') {
    return sendJSON(res, 400, { error: 'to, ciphertext, iv required' });
  }
  if (!users[to]) return sendJSON(res, 404, { error: 'recipient does not exist' });
  const msg = { id: crypto.randomBytes(12).toString('hex'), from: username, ciphertext, iv, ts: Date.now() };
  if (!messageQueue[to]) messageQueue[to] = [];
  messageQueue[to].push(msg);
  if (messageQueue[to].length > 500) messageQueue[to] = messageQueue[to].slice(-500);
  persistMessages();
  const list = waiters.get(to);
  if (list && list.length) list.splice(0).forEach((resolve) => resolve());
  sendJSON(res, 200, { ok: true, id: msg.id });
}

function popMessagesFor(username) {
  const list = messageQueue[username] || [];
  messageQueue[username] = [];
  if (list.length) persistMessages();
  return list;
}

async function handlePoll(req, res) {
  const username = authenticate(req);
  if (!username) return sendJSON(res, 401, { error: 'not authenticated' });

  const immediate = popMessagesFor(username);
  if (immediate.length) return sendJSON(res, 200, { messages: immediate });

  // Long-poll: hold the request open up to 25s so new messages arrive
  // in near-real-time without needing WebSockets.
  let done = false;
  const timer = setTimeout(() => {
    if (done) return;
    done = true;
    cleanup();
    sendJSON(res, 200, { messages: popMessagesFor(username) });
  }, 25000);

  function onWake() {
    if (done) return;
    done = true;
    clearTimeout(timer);
    cleanup();
    sendJSON(res, 200, { messages: popMessagesFor(username) });
  }
  function cleanup() {
    const list = waiters.get(username);
    if (!list) return;
    const idx = list.indexOf(onWake);
    if (idx !== -1) list.splice(idx, 1);
  }

  if (!waiters.has(username)) waiters.set(username, []);
  waiters.get(username).push(onWake);

  req.on('close', () => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    cleanup();
  });
}

const server = http.createServer(async (req, res) => {
  const parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsed.pathname;

  try {
    if (pathname === '/api/register' && req.method === 'POST') return await handleRegister(req, res);
    if (pathname === '/api/login' && req.method === 'POST') return await handleLogin(req, res);
    if (pathname === '/api/publickey' && req.method === 'POST') return await handlePublicKeyUpload(req, res);
    if (pathname.startsWith('/api/publickey/') && req.method === 'GET') {
      return handlePublicKeyFetch(req, res, decodeURIComponent(pathname.slice('/api/publickey/'.length)));
    }
    if (pathname === '/api/send' && req.method === 'POST') return await handleSend(req, res);
    if (pathname === '/api/poll' && req.method === 'GET') return await handlePoll(req, res);
    if (pathname.startsWith('/api/')) return sendJSON(res, 404, { error: 'not found' });
    return serveStatic(req, res, pathname);
  } catch (err) {
    console.error(err);
    if (!res.headersSent) sendJSON(res, 500, { error: 'server error' });
  }
});

server.listen(PORT, () => {
  console.log(`Relay listening on http://localhost:${PORT}`);
});
