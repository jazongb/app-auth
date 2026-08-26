// Proves the codec reproduces an existing hand-rolled session cookie
// byte-for-byte, for each of the three layouts it supports.
//
// These are not decorative. If one fails, adopting this package silently
// invalidates every cookie that layout has already issued, and every holder is
// signed out on the next deploy with no warning.
//
// Each `legacy*` function is a transcription of a real implementation, kept as
// the reference behaviour the codec has to match. When adopting the package in
// an app, transcribe ITS session code the same way and add a case.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sessionCodec } from '../dist/index.js';

const SECRET = 'test-secret-not-a-real-one';
const EXPIRES = 1893456000000; // fixed, so signatures are deterministic

async function hmacBytes(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(message)));
}

// --- Variant A: `<prefix>:<expires>` + Buffer hex ---
async function legacyA(expires) {
  const payload = `app:${expires}`;
  const sig = Buffer.from(await hmacBytes(SECRET, payload)).toString('hex');
  return `${payload}.${sig}`;
}

// --- Variant B: bare `<ISSUED AT>` + Buffer base64url ---
// Note this one stores the ISSUE time, not the expiry, and verifies with
// `Date.now() - ts < TTL_MS`. Reading it as an expiry would treat every live
// cookie as long expired.
async function legacyB(issuedAt) {
  const payload = String(issuedAt);
  const sig = Buffer.from(await hmacBytes(SECRET, payload)).toString('base64url');
  return `${payload}.${sig}`;
}

// --- Variant C: `<b64url(username)>.<expires>` + hand-rolled base64url ---
// Note the payload itself contains a '.', so the token has THREE segments.
function b64urlC(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function legacyC(expires, username) {
  const payload = `${b64urlC(new TextEncoder().encode(username))}.${expires}`;
  return `${payload}.${b64urlC(await hmacBytes(SECRET, payload))}`;
}

// The codec stamps Date.now(); pin it so output is comparable.
async function createAt(codec, target, ttlMs, subject) {
  const realNow = Date.now;
  Date.now = () => target - ttlMs;
  try { return await codec.create(subject); } finally { Date.now = realNow; }
}

const TTL = 30 * 24 * 60 * 60 * 1000;

test('variant A: prefixed + hex is byte-identical', async () => {
  const codec = sessionCodec({ cookieName: 'app_session', secret: SECRET, prefix: 'app', encoding: 'hex' });
  assert.equal(await createAt(codec, EXPIRES, TTL), await legacyA(EXPIRES));
});

test('variant B: bare + base64url with issued-at semantics', async () => {
  const codec = sessionCodec({
    cookieName: 'app_session', secret: SECRET, prefix: null,
    encoding: 'base64url', stamp: 'issued',
  });
  // Under stamp:'issued' the payload is the moment of creation, so pinning
  // "now" to ISSUED must reproduce the legacy token for that same instant.
  const ISSUED = EXPIRES - TTL;
  assert.equal(await createAt(codec, ISSUED, 0), await legacyB(ISSUED));

  // The case that matters: a cookie minted an hour ago by the existing app must
  // still verify. Under the wrong stamp this returns false and every holder
  // is signed out on deploy.
  assert.equal(await codec.verify(await legacyB(Date.now() - 3600_000)), true);
  assert.equal(await codec.verify(await legacyB(Date.now() - TTL - 1000)), false, 'past TTL');
});

test('reading an issued-at cookie as an expiry fails closed, not open', async () => {
  const wrong = sessionCodec({
    cookieName: 'app_session', secret: SECRET, prefix: null, encoding: 'base64url',
  }); // defaults to stamp:'expires'
  assert.equal(await wrong.verify(await legacyB(Date.now() - 3600_000)), false);
});

test('variant C: subject payload is byte-identical and round-trips', async () => {
  const codec = sessionCodec({
    cookieName: 'app_session', secret: SECRET, format: 'subject', encoding: 'base64url',
  });
  assert.equal(
    await createAt(codec, EXPIRES, TTL, 'shared-user'),
    await legacyC(EXPIRES, 'shared-user')
  );
  // The original implementation's verify returns the username; ours must
  // recover the same one from a token that implementation minted.
  const live = await legacyC(Date.now() + 60_000, 'shared-user');
  assert.deepEqual(await codec.read(live), { subject: 'shared-user' });
});

test('a subject-format token cannot be re-signed under a different subject', async () => {
  const codec = sessionCodec({
    cookieName: 'app_session', secret: SECRET, format: 'subject', encoding: 'base64url',
  });
  const live = await legacyC(Date.now() + 60_000, 'shared-user');
  const forged = live.replace(
    b64urlC(new TextEncoder().encode('shared-user')),
    b64urlC(new TextEncoder().encode('admin'))
  );
  assert.equal(await codec.read(forged), null, 'swapped subject must fail the signature');
});

test('codec verifies tokens the legacy code issued', async () => {
  const codec = sessionCodec({ cookieName: 'app_session', secret: SECRET, prefix: 'app', encoding: 'hex' });
  assert.equal(await codec.verify(await legacyA(Date.now() + 60_000)), true, 'live cookie must still verify');
  assert.equal(await codec.verify(await legacyA(Date.now() - 60_000)), false, 'expired cookie must not');
});

test('tampering and cross-prefix reuse are rejected', async () => {
  const codec = sessionCodec({ cookieName: 'app_session', secret: SECRET, prefix: 'app', encoding: 'hex' });
  const good = await legacyA(Date.now() + 60_000);

  assert.equal(await codec.verify(good.slice(0, -1) + '0'), false, 'flipped signature byte');
  // Built from parts rather than a regex over a literal prefix: a regex that
  // silently stops matching forges nothing and the assertion passes for the
  // wrong reason. (It did exactly that once, which is how this comment exists.)
  const [payload, sig] = [good.slice(0, good.lastIndexOf('.')), good.slice(good.lastIndexOf('.') + 1)];
  const stretched = `${payload.split(':')[0]}:${Date.now() + 9e9}.${sig}`;
  assert.notEqual(stretched, good, 'the forged token must actually differ');
  assert.equal(await codec.verify(stretched), false, 'extended expiry');
  assert.equal(await codec.verify(''), false);
  assert.equal(await codec.verify(undefined), false);
  assert.equal(await codec.verify('no-dot-here'), false);

  // A bare-format cookie must not satisfy a prefixed codec.
  assert.equal(await codec.verify(await legacyB(Date.now() + 60_000)), false, 'cross-format reuse');
});

test('empty secret never verifies', async () => {
  const codec = sessionCodec({ cookieName: 'x', secret: '', prefix: 'app', encoding: 'hex' });
  assert.equal(await codec.verify(await legacyA(Date.now() + 60_000)), false);
});
