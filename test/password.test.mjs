import { test } from 'node:test';
import assert from 'node:assert/strict';
import { signInWithPassword, setPassword, passwordProblem, MIN_PASSWORD_LENGTH } from '../dist/index.js';

const GATE_OK = { ok: true };
const refuse = { ok: false, status: 403, error: 'Not on the list.' };

function fakeClient({ signInResult, getUserResult, updateResult } = {}) {
  const calls = { signOut: 0, update: 0 };
  return {
    calls,
    auth: {
      signInWithPassword: async () => signInResult ?? { data: { user: null }, error: { message: 'bad' } },
      getUser: async () => getUserResult ?? { data: { user: null }, error: null },
      updateUser: async () => { calls.update++; return updateResult ?? { data: { user: null }, error: null }; },
      signOut: async () => { calls.signOut++; },
    },
  };
}

const okUser = { data: { user: { id: 'u1', email: 'someone@example.org' } }, error: null };

test('length is the only rule, and whitespace is rejected', () => {
  assert.equal(passwordProblem('x'.repeat(MIN_PASSWORD_LENGTH)), null);
  assert.match(passwordProblem('short'), /at least/);
  assert.match(passwordProblem(' ' + 'x'.repeat(MIN_PASSWORD_LENGTH)), /space/);
});

test('a correct password still has to pass the admission gate', async () => {
  const c = fakeClient({ signInResult: okUser });
  const res = await signInWithPassword({ supabase: c, email: 'someone@example.org', password: 'x'.repeat(12), confirm: () => refuse });
  assert.equal(res.status, 403);
  // The critical bit: no usable session may survive a refusal, or a user of a
  // different app in the shared auth.users pool keeps a live cookie.
  assert.equal(c.calls.signOut, 1, 'must sign out on refusal');
});

test('a correct password that passes the gate signs in', async () => {
  const c = fakeClient({ signInResult: okUser });
  const res = await signInWithPassword({ supabase: c, email: 'someone@example.org', password: 'x'.repeat(12), confirm: () => GATE_OK });
  assert.equal(res.status, 200);
  assert.equal(c.calls.signOut, 0);
});

test('wrong password and unknown account are indistinguishable', async () => {
  const wrong = await signInWithPassword({
    supabase: fakeClient({ signInResult: { data: { user: null }, error: { message: 'Invalid login credentials' } } }),
    email: 'someone@example.org', password: 'x'.repeat(12), confirm: () => GATE_OK,
  });
  const unknown = await signInWithPassword({
    supabase: fakeClient({ signInResult: { data: { user: null }, error: { message: 'User not found' } } }),
    email: 'nobody@example.org', password: 'x'.repeat(12), confirm: () => GATE_OK,
  });
  assert.deepEqual(wrong, unknown, 'responses must not reveal which addresses exist');
});

test('the gate is checked against the authenticated user, not the posted email', async () => {
  const c = fakeClient({ signInResult: okUser });
  let sawEmail = null;
  await signInWithPassword({
    supabase: c, email: 'ATTACKER-SUPPLIED@example.org', password: 'x'.repeat(12),
    confirm: u => { sawEmail = u.email; return GATE_OK; },
  });
  assert.equal(sawEmail, 'someone@example.org');
});

test('setting a password requires a session', async () => {
  const res = await setPassword({ supabase: fakeClient(), password: 'x'.repeat(12), confirm: () => GATE_OK });
  assert.equal(res.status, 401);
});

test('setting a password re-checks the roster, and refuses without writing', async () => {
  const c = fakeClient({ getUserResult: okUser });
  const res = await setPassword({ supabase: c, password: 'x'.repeat(12), confirm: () => refuse });
  assert.equal(res.status, 403);
  assert.equal(c.calls.update, 0, 'a removed member must not be able to set a password on the way out');
});

test('a too-short password never reaches Supabase', async () => {
  const c = fakeClient({ getUserResult: okUser });
  const res = await setPassword({ supabase: c, password: 'short', confirm: () => GATE_OK });
  assert.equal(res.status, 400);
  assert.equal(c.calls.update, 0);
});

test("Supabase's own rejection is surfaced, not flattened", async () => {
  // 'found in a data breach' is actionable and only Supabase knows it.
  const c = fakeClient({ getUserResult: okUser, updateResult: { data: { user: null }, error: { message: 'This password has been found in a data breach.' } } });
  const res = await setPassword({ supabase: c, password: 'x'.repeat(12), confirm: () => GATE_OK });
  assert.equal(res.status, 400);
  assert.match(String(res.body.error), /data breach/);
});
