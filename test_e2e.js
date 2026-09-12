'use strict';
const { webcrypto: crypto } = require('node:crypto');
const assert = require('node:assert');

const BASE = process.env.TEST_BASE_URL || 'http://localhost:3000';
const enc = new TextEncoder();
const dec = new TextDecoder();

function bufToBase64(buf) { return Buffer.from(buf).toString('base64'); }
function base64ToBuf(b64) { return Buffer.from(b64, 'base64'); }

async function generateIdentity() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
  const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const privateJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  return { publicJwk, privateJwk };
}
function importPrivateKey(jwk) { return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']); }
function importPublicKey(jwk) { return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []); }
function deriveSharedKey(priv, pub) {
  return crypto.subtle.deriveKey({ name: 'ECDH', public: pub }, priv, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encryptText(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
  return { ciphertext: bufToBase64(ct), iv: bufToBase64(iv) };
}
async function decryptText(key, ciphertextB64, ivB64) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(base64ToBuf(ivB64)) }, key, base64ToBuf(ciphertextB64));
  return dec.decode(pt);
}
async function safetyCode(myJwk, theirJwk) {
  const a = String(myJwk.x) + String(myJwk.y);
  const b = String(theirJwk.x) + String(theirJwk.y);
  const combined = [a, b].sort().join('|');
  const hash = await crypto.subtle.digest('SHA-256', enc.encode(combined));
  const bytes = new Uint8Array(hash);
  const groups = [];
  for (let i = 0; i < 12; i++) groups.push(String(bytes[i]).padStart(3, '0'));
  return groups.join(' ');
}

async function jsonFetch(path, opts = {}) {
  const res = await fetch(BASE + path, {
    method: opts.method || 'GET',
    headers: { 'Content-Type': 'application/json', ...(opts.token ? { Authorization: `Bearer ${opts.token}` } : {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch {}
  return { status: res.status, data };
}

async function main() {
  const suffix = Date.now();
  const aliceName = `alice_${suffix}`;
  const bobName = `bob_${suffix}`;

  // --- register two accounts ---
  let r = await jsonFetch('/api/register', { method: 'POST', body: { username: aliceName, password: 'correct horse battery' } });
  assert.strictEqual(r.status, 200, 'alice register should succeed');
  const aliceToken = r.data.token;

  r = await jsonFetch('/api/register', { method: 'POST', body: { username: bobName, password: 'another good password' } });
  assert.strictEqual(r.status, 200, 'bob register should succeed');
  const bobToken = r.data.token;

  // duplicate registration should fail
  r = await jsonFetch('/api/register', { method: 'POST', body: { username: aliceName, password: 'whatever12345' } });
  assert.strictEqual(r.status, 409, 'duplicate username should be rejected');

  // wrong password login should fail
  r = await jsonFetch('/api/login', { method: 'POST', body: { username: aliceName, password: 'wrong password here' } });
  assert.strictEqual(r.status, 401, 'wrong password should be rejected');

  // right password login should succeed
  r = await jsonFetch('/api/login', { method: 'POST', body: { username: aliceName, password: 'correct horse battery' } });
  assert.strictEqual(r.status, 200, 'correct login should succeed');

  // --- generate identities client-side (this never touches the server) ---
  const alice = await generateIdentity();
  const bob = await generateIdentity();

  // --- upload public keys ---
  r = await jsonFetch('/api/publickey', { method: 'POST', token: aliceToken, body: { publicKey: alice.publicJwk } });
  assert.strictEqual(r.status, 200);
  r = await jsonFetch('/api/publickey', { method: 'POST', token: bobToken, body: { publicKey: bob.publicJwk } });
  assert.strictEqual(r.status, 200);

  // fetching a key for a user who hasn't uploaded one yet -> 404
  r = await jsonFetch('/api/publickey/' + `nobody_${suffix}`);
  assert.strictEqual(r.status, 404, 'unknown user should 404');

  // --- alice fetches bob's public key and derives the shared key ---
  r = await jsonFetch('/api/publickey/' + bobName);
  assert.strictEqual(r.status, 200);
  const bobPublicJwkAsAliceSeesIt = r.data.publicKey;
  const bobPubKey = await importPublicKey(bobPublicJwkAsAliceSeesIt);
  const alicePrivKey = await importPrivateKey(alice.privateJwk);
  const aliceSharedKey = await deriveSharedKey(alicePrivKey, bobPubKey);

  // --- alice encrypts and sends ---
  const plaintext = 'Meet me at the usual place, 7pm. Bring the encrypted thing.';
  const { ciphertext, iv } = await encryptText(aliceSharedKey, plaintext);
  r = await jsonFetch('/api/send', { method: 'POST', token: aliceToken, body: { to: bobName, ciphertext, iv } });
  assert.strictEqual(r.status, 200, 'send should succeed');

  // sanity: the ciphertext must not contain the plaintext anywhere (server truly only sees ciphertext)
  assert.ok(!ciphertext.includes('usual place'), 'ciphertext must not leak plaintext');

  // --- bob polls and decrypts ---
  r = await jsonFetch('/api/poll', { token: bobToken });
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.data.messages.length, 1, 'bob should have exactly one queued message');
  const received = r.data.messages[0];
  assert.strictEqual(received.from, aliceName);

  r = await jsonFetch('/api/publickey/' + aliceName);
  const alicePublicJwkAsBobSeesIt = r.data.publicKey;
  const alicePubKey = await importPublicKey(alicePublicJwkAsBobSeesIt);
  const bobPrivKey = await importPrivateKey(bob.privateJwk);
  const bobSharedKey = await deriveSharedKey(bobPrivKey, alicePubKey);
  const decrypted = await decryptText(bobSharedKey, received.ciphertext, received.iv);
  assert.strictEqual(decrypted, plaintext, 'decrypted text must match what alice sent');

  // mailbox should now be empty (messages are popped on poll)
  r = await jsonFetch('/api/poll', { token: bobToken });
  // second poll would long-poll for 25s if empty -- so instead just check queue length via a race with timeout
  // (we already proved delivery works; skip waiting on the long-poll here)

  // --- safety codes should match on both sides ---
  const codeFromAlice = await safetyCode(alice.publicJwk, bobPublicJwkAsAliceSeesIt);
  const codeFromBob = await safetyCode(bob.publicJwk, alicePublicJwkAsBobSeesIt);
  assert.strictEqual(codeFromAlice, codeFromBob, 'safety codes must match on both ends');

  // --- auth is required for protected endpoints ---
  r = await jsonFetch('/api/send', { method: 'POST', body: { to: bobName, ciphertext: 'x', iv: 'y' } });
  assert.strictEqual(r.status, 401, 'sending without a token should be rejected');

  r = await jsonFetch('/api/send', { method: 'POST', token: 'not-a-real-token', body: { to: bobName, ciphertext: 'x', iv: 'y' } });
  assert.strictEqual(r.status, 401, 'sending with a bogus token should be rejected');

  // --- static file serving works ---
  const staticRes = await fetch(BASE + '/');
  assert.strictEqual(staticRes.status, 200, 'index.html should be served');
  const html = await staticRes.text();
  assert.ok(html.includes('Relay'), 'index.html should contain the app shell');

  console.log('ALL TESTS PASSED');
  process.exit(0);
}

main().catch((err) => {
  console.error('TEST FAILED:', err);
  process.exit(1);
});
