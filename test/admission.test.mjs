import { test } from 'node:test';
import assert from 'node:assert/strict';
import { admit, canWrite, requireWrite, requireRole, clientIp } from '../dist/index.js';

const ENV = { ADMIN_EMAILS: 'owner@example.org, MAINTAINER@example.net', TRUSTED_DOMAINS: 'example.net' };
const user = (email, id = 'u1') => ({ id, email });
const noRoster = async () => null;
const roster = roles => async () => ({ roles, name: 'Someone' });

const base = { adminEmailsEnv: 'ADMIN_EMAILS', trustedDomainsEnv: 'TRUSTED_DOMAINS', env: ENV };

test('roster match grants the app-supplied roles', async () => {
  const p = await admit(user('greg@example.com'), { ...base, resolveRoster: roster(['physician', 'member']) });
  assert.deepEqual(p.roles, ['physician', 'member']);
  assert.equal(p.admittedVia, 'roster');
  assert.equal(canWrite(p), true);
});

test('admin allowlist is case-insensitive and stacks onto roster roles', async () => {
  const p = await admit(user('Owner@Example.org'), { ...base, resolveRoster: roster(['member']) });
  assert.deepEqual(p.roles, ['member', 'admin']);
});

test('an allowlisted admin with no roster row still gets in', async () => {
  const p = await admit(user('maintainer@example.net'), { ...base, resolveRoster: noRoster });
  assert.deepEqual(p.roles, ['admin']);
});

test('signed in but on nobody list is denied — a session is not permission', async () => {
  // This is the case that matters when several apps share one Supabase
  // project: the session is real, it just belongs to a different app's user.
  const p = await admit(user('stranger@elsewhere.com'), { ...base, resolveRoster: noRoster });
  assert.deepEqual(p.roles, []);
  assert.equal(p.admittedVia, 'none');
  assert.equal(canWrite(p), false);
});

test('trusted domain admits as member when the roster does not know them', async () => {
  const p = await admit(user('newperson@example.net'), { ...base, resolveRoster: noRoster });
  assert.deepEqual(p.roles, ['member']);
  assert.equal(p.admittedVia, 'domain');
});

test('domain matching is exact — a lookalike suffix must not match', async () => {
  const p = await admit(user('x@notexample.net'), { ...base, resolveRoster: noRoster });
  assert.equal(p.admittedVia, 'none');
  const q = await admit(user('x@example.net.evil.com'), { ...base, resolveRoster: noRoster });
  assert.equal(q.admittedVia, 'none');
});

test('network admission yields a guest that can never write', async () => {
  const cfg = { ...base, resolveRoster: noRoster, matchNetwork: ip => ip === '203.0.113.7' };
  const p = await admit(null, cfg, '203.0.113.7');
  assert.deepEqual(p.roles, ['guest']);
  assert.equal(p.admittedVia, 'network');
  assert.equal(canWrite(p), false);
  assert.equal(requireWrite(p).ok, false);
  assert.equal(requireRole(p, 'guest').ok, true);

  assert.equal((await admit(null, cfg, '198.51.100.1')).admittedVia, 'none');
});

test('network rules never apply to a signed-in user', async () => {
  // Otherwise being on the trusted network would silently upgrade a refused
  // sign-in into an admitted one.
  const cfg = { ...base, resolveRoster: noRoster, matchNetwork: () => true };
  const p = await admit(user('stranger@elsewhere.com'), cfg, '203.0.113.7');
  assert.equal(p.admittedVia, 'none');
});

test('a network-admitted principal cannot write even if given member', async () => {
  const cfg = { ...base, resolveRoster: noRoster, matchNetwork: () => true, networkRoles: ['member'] };
  const p = await admit(null, cfg, '1.2.3.4');
  assert.equal(canWrite(p), false, 'admittedVia network must veto writes');
});

test('nobody signed in and no network rule is denied', async () => {
  assert.equal((await admit(null, { ...base, resolveRoster: noRoster })).admittedVia, 'none');
});

test('clientIp takes the first x-forwarded-for entry', () => {
  assert.equal(clientIp(new Headers({ 'x-forwarded-for': '203.0.113.7, 10.0.0.1' })), '203.0.113.7');
  assert.equal(clientIp(new Headers({ 'x-real-ip': '198.51.100.4' })), '198.51.100.4');
  assert.equal(clientIp(new Headers()), null);
});
