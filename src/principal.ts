// The one shape every app in this family agrees on.
//
// A Principal is whoever is making the current request. It is deliberately
// small: an identity, a set of roles, and a record of HOW they were admitted.
// Everything app-specific — which table the roles came from, what a role
// lets you do — lives in the app, not here. That is what makes this package
// reusable across unrelated Supabase projects and unrelated schemas.

/** Built-in roles every app understands. Apps may add their own strings. */
export type CoreRole = 'guest' | 'member' | 'admin';

export type Role = CoreRole | (string & {});

/** How this principal got in. Useful for audit, and for capping trust. */
export type AdmissionSource =
  | 'roster'    // matched an explicit row the app looks up
  | 'domain'    // matched a trusted email domain rule
  | 'network'   // matched a trusted network (e.g. office wifi) — see admission.ts
  | 'secret'    // presented a shared secret (the legacy shared-password tier)
  | 'none';     // not admitted

export interface Principal {
  /** Supabase auth.users id, when the principal signed in by email. */
  userId: string | null;
  /** Verified email, when there is one. Never a client-supplied value. */
  email: string | null;
  /** Display name, if the app's resolver supplied one. */
  name: string | null;
  roles: Role[];
  admittedVia: AdmissionSource;
}

export const ANONYMOUS: Principal = Object.freeze({
  userId: null,
  email: null,
  name: null,
  roles: [] as Role[],
  admittedVia: 'none' as const,
});

export function hasRole(p: Principal | null | undefined, role: Role): boolean {
  return !!p && p.roles.includes(role);
}

export function isAdmin(p: Principal | null | undefined): boolean {
  return hasRole(p, 'admin');
}

/**
 * True when the principal may perform a write.
 *
 * A `guest` never can, regardless of any other role it somehow acquired —
 * a network-admitted principal is a low-trust signal, since all it establishes
 * is that someone is on that network, so this package refuses to let that path
 * grant write access. Apps
 * that want a different rule should check roles directly rather than widen
 * this one.
 */
export function canWrite(p: Principal | null | undefined): boolean {
  if (!p || p.roles.length === 0) return false;
  if (p.admittedVia === 'network' || hasRole(p, 'guest')) return false;
  return hasRole(p, 'member') || hasRole(p, 'admin');
}
