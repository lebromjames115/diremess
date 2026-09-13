'use strict';
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'data', 'db.json');

function ensureDb() {
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify({ users: {}, mailboxes: {}, groups: {}, contacts: {} }, null, 2));
  }
}

function readDb() {
  ensureDb();
  const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  // Backfill for db.json files written before groups/contacts existed.
  if (!db.groups) db.groups = {};
  if (!db.contacts) db.contacts = {};
  // 'off' was removed as a disappearing-messages mode (messages are never
  // permanently stored anymore) — normalize any groups created before that
  // change so they don't reference a mode the rest of the app no longer
  // recognizes. This gets persisted the next time anything writes the db.
  for (const g of Object.values(db.groups)) {
    if (g.disappearing === 'off') g.disappearing = 'instant';
  }
  return db;
}

function writeDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

// Every caller's read-modify-write is chained onto this promise, so concurrent
// requests never interleave and clobber each other's changes.
let writeChain = Promise.resolve();

function transact(fn) {
  const result = writeChain.then(async () => {
    const db = readDb();
    const out = await fn(db);
    writeDb(db);
    return out;
  });
  // Keep the chain alive even if this transaction throws.
  writeChain = result.catch(() => {});
  return result;
}

module.exports = { transact };
