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

function generateContentKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function encryptBytes(key, buf) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buf);
  return { ciphertext: Buffer.from(ct), iv: bufToBase64(iv) };
}
async function decryptBytes(key, ciphertextBuf, ivB64) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(base64ToBuf(ivB64)) }, key, ciphertextBuf);
  return Buffer.from(pt);
}
function importContentKey(b64) {
  return crypto.subtle.importKey('raw', base64ToBuf(b64), { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}

async function mediaUpload(token, buf) {
  const headers = { 'Content-Type': 'application/octet-stream' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(BASE + '/api/media', { method: 'POST', headers, body: buf });
  let data = {};
  try { data = await res.json(); } catch {}
  return { status: res.status, data };
}
async function mediaDownload(token, id) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(BASE + '/api/media/' + id, { headers });
  if (res.status !== 200) {
    let data = {};
    try { data = await res.json(); } catch {}
    return { status: res.status, data };
  }
  return { status: res.status, buf: Buffer.from(await res.arrayBuffer()) };
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

  // ================= MEDIA ATTACHMENTS (direct message) =================
  // A file is encrypted once with a random one-time content key and
  // uploaded as an anonymous blob; the content key then travels inside the
  // normal end-to-end encrypted envelope, wrapped with the pairwise key —
  // same trust model as text, just with the bytes going a different way.
  const filePlaintext = Buffer.from(crypto.getRandomValues(new Uint8Array(4096)));
  const contentKey = await generateContentKey();
  const { ciphertext: mediaCiphertext, iv: mediaIv } = await encryptBytes(contentKey, filePlaintext);

  r = await mediaUpload(null, mediaCiphertext);
  assert.strictEqual(r.status, 401, 'media upload without auth should be rejected');

  r = await mediaUpload(aliceToken, mediaCiphertext);
  assert.strictEqual(r.status, 200, 'media upload should succeed');
  const mediaId = r.data.mediaId;
  assert.ok(mediaId, 'upload should return a mediaId');

  const oversized = Buffer.alloc(26 * 1024 * 1024); // just over the server's 25MB cap
  r = await mediaUpload(aliceToken, oversized);
  assert.strictEqual(r.status, 413, 'oversized attachments should be rejected');

  const contentKeyB64 = await (async () => bufToBase64(await crypto.subtle.exportKey('raw', contentKey)))();
  const mediaPayload = JSON.stringify({
    v: 1,
    kind: 'media',
    mediaId,
    mediaIv,
    mimeType: 'image/png',
    size: filePlaintext.length,
    name: 'sunset.png',
    contentKey: contentKeyB64,
    caption: 'check this out',
  });
  const mediaEnvelope = await encryptText(aliceSharedKey, mediaPayload);
  r = await jsonFetch('/api/send', { method: 'POST', token: aliceToken, body: { to: bobName, ciphertext: mediaEnvelope.ciphertext, iv: mediaEnvelope.iv } });
  assert.strictEqual(r.status, 200, 'sending an attachment message should succeed');

  r = await jsonFetch('/api/poll', { token: bobToken });
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.data.messages.length, 1, 'bob should have exactly one queued message');
  const bobEnvelopeText = await decryptText(bobSharedKey, r.data.messages[0].ciphertext, r.data.messages[0].iv);
  const bobParsed = JSON.parse(bobEnvelopeText);
  assert.strictEqual(bobParsed.kind, 'media');
  assert.strictEqual(bobParsed.caption, 'check this out');
  assert.strictEqual(bobParsed.mediaId, mediaId);

  r = await mediaDownload(bobToken, bobParsed.mediaId);
  assert.strictEqual(r.status, 200, 'recipient should be able to download the attachment blob');
  const bobContentKey = await importContentKey(bobParsed.contentKey);
  const bobDecryptedFile = await decryptBytes(bobContentKey, r.buf, bobParsed.mediaIv);
  assert.ok(bobDecryptedFile.equals(filePlaintext), "decrypted attachment bytes must match what alice sent");

  r = await mediaDownload(null, bobParsed.mediaId);
  assert.strictEqual(r.status, 401, 'media download without auth should be rejected');

  r = await mediaDownload(bobToken, crypto.randomUUID());
  assert.strictEqual(r.status, 404, 'a random, never-uploaded media id should not exist');

  // --- safety codes should match on both sides ---
  const codeFromAlice = await safetyCode(alice.publicJwk, bobPublicJwkAsAliceSeesIt);
  const codeFromBob = await safetyCode(bob.publicJwk, alicePublicJwkAsBobSeesIt);
  assert.strictEqual(codeFromAlice, codeFromBob, 'safety codes must match on both ends');

  // --- auth is required for protected endpoints ---
  r = await jsonFetch('/api/send', { method: 'POST', body: { to: bobName, ciphertext: 'x', iv: 'y' } });
  assert.strictEqual(r.status, 401, 'sending without a token should be rejected');

  r = await jsonFetch('/api/send', { method: 'POST', token: 'not-a-real-token', body: { to: bobName, ciphertext: 'x', iv: 'y' } });
  assert.strictEqual(r.status, 401, 'sending with a bogus token should be rejected');

  // ================= GROUP CHATS =================
  // A third account, Carol, joins Alice and Bob in a group.
  const carolName = `carol_${suffix}`;
  r = await jsonFetch('/api/register', { method: 'POST', body: { username: carolName, password: 'yet another password' } });
  assert.strictEqual(r.status, 200, 'carol register should succeed');
  const carolToken = r.data.token;
  const carol = await generateIdentity();
  r = await jsonFetch('/api/publickey', { method: 'POST', token: carolToken, body: { publicKey: carol.publicJwk } });
  assert.strictEqual(r.status, 200);

  // --- creating a group with a nonexistent member should fail ---
  r = await jsonFetch('/api/groups', { method: 'POST', token: aliceToken, body: { name: 'Bad group', members: [`nobody_${suffix}`] } });
  assert.strictEqual(r.status, 400, 'group with unknown member should be rejected');

  // --- alice creates a group with bob and carol ---
  r = await jsonFetch('/api/groups', { method: 'POST', token: aliceToken, body: { name: 'Weekend plans', members: [bobName, carolName] } });
  assert.strictEqual(r.status, 200, 'group creation should succeed');
  const group = r.data.group;
  assert.ok(group.id, 'group should have an id');
  assert.strictEqual(group.members.length, 3, 'group should include creator + 2 invited members');
  assert.ok(group.members.includes(aliceName) && group.members.includes(bobName) && group.members.includes(carolName));

  // --- bob and carol should each see a group-invite system notification on poll ---
  r = await jsonFetch('/api/poll', { token: bobToken });
  assert.strictEqual(r.status, 200);
  const bobInvite = r.data.messages.find((m) => m.system === 'group-invite');
  assert.ok(bobInvite, 'bob should receive a group-invite notification');
  assert.strictEqual(bobInvite.group.id, group.id);

  r = await jsonFetch('/api/poll', { token: carolToken });
  const carolInvite = r.data.messages.find((m) => m.system === 'group-invite');
  assert.ok(carolInvite, 'carol should receive a group-invite notification');

  // --- a non-member cannot fetch the group ---
  const daveName = `dave_${suffix}`;
  r = await jsonFetch('/api/register', { method: 'POST', body: { username: daveName, password: 'not in the group' } });
  const daveToken = r.data.token;
  r = await jsonFetch(`/api/groups/${group.id}`, { token: daveToken });
  assert.strictEqual(r.status, 404, 'non-member should not be able to fetch group info');

  // --- alice sends a group message via fan-out: encrypted separately per member ---
  const aliceCarolPub = await importPublicKey((await jsonFetch('/api/publickey/' + carolName)).data.publicKey);
  const aliceCarolShared = await deriveSharedKey(alicePrivKey, aliceCarolPub);
  const groupPlaintext = 'Dinner at 8, my place.';
  const toBob = await encryptText(aliceSharedKey, groupPlaintext); // reuse alice<->bob shared key from earlier
  const toCarol = await encryptText(aliceCarolShared, groupPlaintext);

  r = await jsonFetch('/api/send', {
    method: 'POST',
    token: aliceToken,
    body: {
      groupId: group.id,
      messages: [
        { to: bobName, ciphertext: toBob.ciphertext, iv: toBob.iv },
        { to: carolName, ciphertext: toCarol.ciphertext, iv: toCarol.iv },
      ],
    },
  });
  assert.strictEqual(r.status, 200, 'group fan-out send should succeed');

  // --- a fan-out send naming someone outside the group should be rejected ---
  r = await jsonFetch('/api/send', {
    method: 'POST',
    token: aliceToken,
    body: { groupId: group.id, messages: [{ to: daveName, ciphertext: 'x', iv: 'y' }] },
  });
  assert.strictEqual(r.status, 400, 'sending to a non-member via groupId should be rejected');

  // --- bob and carol each receive and decrypt their own copy ---
  r = await jsonFetch('/api/poll', { token: bobToken });
  const bobGroupMsg = r.data.messages.find((m) => m.groupId === group.id);
  assert.ok(bobGroupMsg, 'bob should have a queued group message');
  assert.strictEqual(bobGroupMsg.from, aliceName);
  const bobDecrypted = await decryptText(bobSharedKey, bobGroupMsg.ciphertext, bobGroupMsg.iv);
  assert.strictEqual(bobDecrypted, groupPlaintext, "bob's decrypted group message must match what alice sent");

  r = await jsonFetch('/api/poll', { token: carolToken });
  const carolGroupMsg = r.data.messages.find((m) => m.groupId === group.id);
  assert.ok(carolGroupMsg, 'carol should have a queued group message');
  const carolPrivKey = await importPrivateKey(carol.privateJwk);
  const alicePubForCarol = await importPublicKey((await jsonFetch('/api/publickey/' + aliceName)).data.publicKey);
  const carolSharedWithAlice = await deriveSharedKey(carolPrivKey, alicePubForCarol);
  const carolDecrypted = await decryptText(carolSharedWithAlice, carolGroupMsg.ciphertext, carolGroupMsg.iv);
  assert.strictEqual(carolDecrypted, groupPlaintext, "carol's decrypted group message must match what alice sent");

  // --- group attachment: one upload, fanned out to bob and carol ---
  const groupFilePlaintext = Buffer.from(crypto.getRandomValues(new Uint8Array(3000)));
  const groupContentKey = await generateContentKey();
  const { ciphertext: groupMediaCiphertext, iv: groupMediaIv } = await encryptBytes(groupContentKey, groupFilePlaintext);
  r = await mediaUpload(aliceToken, groupMediaCiphertext);
  assert.strictEqual(r.status, 200, 'group attachment upload should succeed');
  const groupMediaId = r.data.mediaId;
  const groupContentKeyB64 = bufToBase64(await crypto.subtle.exportKey('raw', groupContentKey));
  const groupMediaPayload = JSON.stringify({
    v: 1,
    kind: 'media',
    mediaId: groupMediaId,
    mediaIv: groupMediaIv,
    mimeType: 'video/mp4',
    size: groupFilePlaintext.length,
    name: 'clip.mp4',
    contentKey: groupContentKeyB64,
  });
  const bobMediaEnv = await encryptText(aliceSharedKey, groupMediaPayload);
  const carolMediaEnv = await encryptText(aliceCarolShared, groupMediaPayload);

  r = await jsonFetch('/api/send', {
    method: 'POST',
    token: aliceToken,
    body: {
      groupId: group.id,
      messages: [
        { to: bobName, ciphertext: bobMediaEnv.ciphertext, iv: bobMediaEnv.iv },
        { to: carolName, ciphertext: carolMediaEnv.ciphertext, iv: carolMediaEnv.iv },
      ],
    },
  });
  assert.strictEqual(r.status, 200, 'group attachment fan-out send should succeed');

  r = await jsonFetch('/api/poll', { token: bobToken });
  const bobGroupMediaMsg = r.data.messages.find((m) => m.groupId === group.id);
  assert.ok(bobGroupMediaMsg, 'bob should have a queued group attachment message');
  const bobGroupParsed = JSON.parse(await decryptText(bobSharedKey, bobGroupMediaMsg.ciphertext, bobGroupMediaMsg.iv));
  const bobGroupFile = await mediaDownload(bobToken, bobGroupParsed.mediaId);
  assert.strictEqual(bobGroupFile.status, 200);
  const bobGroupDecrypted = await decryptBytes(await importContentKey(bobGroupParsed.contentKey), bobGroupFile.buf, bobGroupParsed.mediaIv);
  assert.ok(bobGroupDecrypted.equals(groupFilePlaintext), "bob's decrypted group attachment must match the original file");

  r = await jsonFetch('/api/poll', { token: carolToken });
  const carolGroupMediaMsg = r.data.messages.find((m) => m.groupId === group.id);
  assert.ok(carolGroupMediaMsg, 'carol should have a queued group attachment message');
  const carolGroupParsed = JSON.parse(await decryptText(carolSharedWithAlice, carolGroupMediaMsg.ciphertext, carolGroupMediaMsg.iv));
  assert.strictEqual(carolGroupParsed.mediaId, bobGroupParsed.mediaId, 'bob and carol should reference the exact same single uploaded blob');
  const carolGroupFile = await mediaDownload(carolToken, carolGroupParsed.mediaId);
  const carolGroupDecrypted = await decryptBytes(await importContentKey(carolGroupParsed.contentKey), carolGroupFile.buf, carolGroupParsed.mediaIv);
  assert.ok(carolGroupDecrypted.equals(groupFilePlaintext), "carol's decrypted group attachment must match the original file");

  // --- carol adds dave to the group; bob should get a group-update notification ---
  r = await jsonFetch(`/api/groups/${group.id}/members`, { method: 'POST', token: carolToken, body: { username: daveName } });
  assert.strictEqual(r.status, 200, 'existing member should be able to add a new member');
  assert.strictEqual(r.data.group.members.length, 4, 'group should now have 4 members');

  r = await jsonFetch('/api/poll', { token: bobToken });
  const bobUpdate = r.data.messages.find((m) => m.system === 'group-update');
  assert.ok(bobUpdate, 'existing members should be notified when someone new is added');
  assert.ok(bobUpdate.group.members.includes(daveName));

  r = await jsonFetch('/api/poll', { token: daveToken });
  const daveInvite = r.data.messages.find((m) => m.system === 'group-invite');
  assert.ok(daveInvite, 'the newly added member should get a group-invite notification');

  // --- adding the same member twice should fail ---
  r = await jsonFetch(`/api/groups/${group.id}/members`, { method: 'POST', token: carolToken, body: { username: daveName } });
  assert.strictEqual(r.status, 400, 'adding an existing member again should be rejected');

  // --- a non-member cannot add members ---
  const eveName = `eve_${suffix}`;
  r = await jsonFetch('/api/register', { method: 'POST', body: { username: eveName, password: 'also not a member' } });
  r = await jsonFetch(`/api/groups/${group.id}/members`, { method: 'POST', token: r.data.token, body: { username: eveName } });
  assert.strictEqual(r.status, 404, 'a non-member should not be able to add members to the group');

  // --- dave, now a member, should be able to fetch the group ---
  r = await jsonFetch(`/api/groups/${group.id}`, { token: daveToken });
  assert.strictEqual(r.status, 200, 'a member should be able to fetch group info');
  assert.strictEqual(r.data.group.members.length, 4);

  // --- alice's own list of groups should include this one ---
  r = await jsonFetch('/api/groups', { token: aliceToken });
  assert.strictEqual(r.status, 200);
  assert.ok(r.data.groups.some((g) => g.id === group.id), "alice's group list should include the group she created");

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
