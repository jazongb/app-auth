// The admission pipeline.
//
// Every app in this family answers "who is this and what may they do?" the
// same way, in the same order, with the same fail-closed default:
//
//   1. roster   — the app looks the verified email up in its own tables
//   2. domain   — the email's domain is on a trusted-domain allowlist
//   3. network  — the request came from a trusted network        [scaffolded]
//   4. deny
//
// The app supplies step 1 as a callback and never sees the rest. That is the
// whole portability story: this file names no table, no schema, and no
// Supabase project, so two unrelated apps can share it while resolving
// completely different rosters against different databases.

import type { User } from '@supabase/supabase-js';
import { ANONYMOUS, type Principal, type Role } from './principal';
import { isDomainListed, isListed } from './allowlist';

/**
 * App-supplied roster lookup. Receives the user Supabase actually
 * authenticated — never a client-supplied address — and returns the roles
 * that user holds, or null if they are not on the app's roster.
 */
export type ResolveRoster = (
  user: User
) => Promise<{ roles: Role[]; name?: string | null } | null>;

export interface AdmissionConfig {
  /** Step 1. Required — this is the app's own membership check. */
  resolveRoster: ResolveRoster;
  /**
   * Env var naming the admin allowlist. Admin is granted on top of whatever
   * the roster returned, and is the ONLY role this package grants directly.
   */
  adminEmailsEnv?: string;
  /**
   * Step 2. Env var naming trusted email domains. A domain match admits the
   * user as `member` when the roster did not recognise them — use it to skip
   * manual roster maintenance for a whole organisation.
   */
  trustedDomainsEnv?: string;
  /** Roles granted by a domain match. Defaults to ['member']. */
  domainRoles?: Role[];
  /**
   * Step 3 — SCAFFOLDED, NOT WIRED.
   *
   * Supply a matcher to admit unauthenticated visitors arriving from a
   * trusted network (e.g. an office's static public IP) as a capped `guest`.
   *
   * Read this before enabling it: a network match identifies a *network*,
   * not a person. Everyone on that wifi matches, including whoever happens to
   * be sitting in the waiting area, and a returning laptop on a dynamic ISP
   * address may stop matching without warning. `guest` is therefore refused write access by
   * `canWrite()` and can never be elevated by this pipeline. Treat it as
   * "skip the sign-in wall for read-only convenience", never as identity.
   */
  matchNetwork?: (ip: string | null) => boolean;
  /** Roles granted by a network match. Defaults to ['guest']. */
  networkRoles?: Role[];
  env?: Record<string, string | undefined>;
}

/**
 * Resolve a Principal for a request.
 *
 * `user` is the Supabase-authenticated user, or null when nobody is signed
 * in. `ip` is the client address, used only by the network step.
 */
export async function admit(
  user: User | null,
  cfg: AdmissionConfig,
  ip: string | null = null
): Promise<Principal> {
  const env = cfg.env ?? process.env;

  if (user?.email) {
    const email = user.email;
    const admin = cfg.adminEmailsEnv
      ? isListed(email, cfg.adminEmailsEnv, env)
      : false;

    // 1. Roster.
    const rostered = await cfg.resolveRoster(user);
    if (rostered) {
      const roles = dedupe([...rostered.roles, ...(admin ? ['admin' as Role] : [])]);
      return { userId: user.id, email, name: rostered.name ?? null, roles, admittedVia: 'roster' };
    }

    // An allowlisted admin is admitted even with no roster row. Without this,
    // adding a maintainer would mean a database edit as well as an env change,
    // which defeats the point of keeping elevation out of the database.
    if (admin) {
      return { userId: user.id, email, name: null, roles: ['admin'], admittedVia: 'roster' };
    }

    // 2. Trusted domain.
    if (cfg.trustedDomainsEnv && isDomainListed(email, cfg.trustedDomainsEnv, env)) {
      return {
        userId: user.id,
        email,
        name: null,
        roles: dedupe(cfg.domainRoles ?? ['member']),
        admittedVia: 'domain',
      };
    }

    // Signed in, but on nobody's list. Fail closed — a Supabase session is
    // not by itself permission to be here. Apps sharing one Supabase project
    // also share its auth.users pool, so a valid session may well belong to a
    // different app's user.
    return ANONYMOUS;
  }

  // 3. Network — only ever reached when nobody is signed in.
  if (cfg.matchNetwork?.(ip)) {
    return {
      userId: null,
      email: null,
      name: null,
      roles: dedupe(cfg.networkRoles ?? ['guest']),
      admittedVia: 'network',
    };
  }

  // 4. Deny.
  return ANONYMOUS;
}

function dedupe(roles: Role[]): Role[] {
  return [...new Set(roles)];
}

/**
 * Best-effort client IP from proxy headers. Vercel sets x-forwarded-for with
 * the client first. Only ever use this for low-trust signals: a header is
 * forgeable by anything between the client and the trusted proxy.
 */
export function clientIp(headers: Headers): string | null {
  const xff = headers.get('x-forwarded-for');
  if (xff) return xff.split(',')[0]!.trim() || null;
  return headers.get('x-real-ip');
}
