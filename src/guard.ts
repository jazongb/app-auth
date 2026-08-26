// Route guards.
//
// These return a Principal or an error shape; they never throw and never
// redirect. Redirect targets are an app decision, so the app decides what to
// do with a refusal.

import { canWrite, hasRole, type Principal, type Role } from './principal';

export type GuardResult =
  | { ok: true; principal: Principal }
  | { ok: false; status: number; error: string };

export function requireSignedIn(p: Principal): GuardResult {
  if (!p.userId) {
    return { ok: false, status: 401, error: 'Sign in to continue.' };
  }
  return { ok: true, principal: p };
}

export function requireRole(p: Principal, role: Role, label?: string): GuardResult {
  if (!hasRole(p, role)) {
    return {
      ok: false,
      status: p.userId ? 403 : 401,
      error: label ?? `This action requires the "${role}" role.`,
    };
  }
  return { ok: true, principal: p };
}

export function requireAnyRole(p: Principal, roles: Role[], label?: string): GuardResult {
  if (!roles.some(r => hasRole(p, r))) {
    return {
      ok: false,
      status: p.userId ? 403 : 401,
      error: label ?? 'You do not have access to this.',
    };
  }
  return { ok: true, principal: p };
}

/** Guest and network-admitted principals are refused here by design. */
export function requireWrite(p: Principal, label?: string): GuardResult {
  if (!canWrite(p)) {
    return {
      ok: false,
      status: p.userId ? 403 : 401,
      error: label ?? 'You do not have permission to make changes.',
    };
  }
  return { ok: true, principal: p };
}
