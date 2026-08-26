// Email + password sign-in, alongside the emailed-code flow.
//
// This exists for ergonomics, not security: a password manager fills a
// password instantly, where a code costs an inbox round-trip. The code flow
// remains the source of truth for identity and is never removed — it is how
// people get their first session, and how they recover a forgotten password.
//
// THE RULE THAT MATTERS HERE: a password proves possession of a credential,
// nothing more. It does NOT prove the holder belongs in this app. When several
// apps share one Supabase project they share its auth.users pool, so a valid
// password may belong to an entirely different app's user. Every entry point
// therefore runs the SAME admission gate the code path runs, and signs the
// user out on refusal so no half-authenticated session survives.
//
// There is deliberately no password-reset email. It would be a second
// code-to-the-same-inbox mechanism with no capability the sign-in code lacks,
// and each additional Supabase email template is another default that ships
// with a URL in it — another place the no-links-in-email rule can silently
// regress. Forgetting a password is handled by signing in with a code and
// setting a new one.

import type { OtpGateResult } from './otp';

/**
 * Narrow structural client, for the same reason OtpClient is narrow:
 * supabase-js's client class has protected members, so passing the class
 * across a .d.ts boundary drags in nominal typing and fails between
 * structurally identical declarations.
 */
export interface PasswordClient {
  auth: {
    signInWithPassword(params: { email: string; password: string }): Promise<{
      data: { user: { id: string; email?: string | null } | null };
      error: { message: string } | null;
    }>;
    updateUser(params: { password?: string; data?: Record<string, unknown> }): Promise<{
      data: { user: { id: string; email?: string | null } | null };
      error: { message: string } | null;
    }>;
    getUser(): Promise<{
      data: {
        user: {
          id: string;
          email?: string | null;
          user_metadata?: Record<string, unknown> | null;
        } | null;
      };
      error: { message: string } | null;
    }>;
    signOut(): Promise<unknown>;
  };
}

/**
 * Minimum length this package will accept.
 *
 * Length is the only rule enforced here. Composition rules (a digit, a symbol,
 * mixed case) push people towards predictable substitutions and away from
 * password managers, which is the opposite of what helps. Pair this with
 * Supabase's leaked-password protection, which checks the actual password
 * against known breaches — a far better signal than counting character classes.
 */
export const MIN_PASSWORD_LENGTH = 12;

export function passwordProblem(password: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Use at least ${MIN_PASSWORD_LENGTH} characters.`;
  }
  // Guard against a password manager or form autofill submitting whitespace.
  if (password.trim().length !== password.length) {
    return 'Password cannot start or end with a space.';
  }
  return null;
}

export interface SignInWithPasswordOptions {
  supabase: PasswordClient;
  email: string;
  password: string;
  /**
   * The SAME admission check the code path runs, against the user Supabase
   * actually authenticated — never the address posted by the client.
   */
  confirm: (user: { id: string; email: string }) => Promise<OtpGateResult> | OtpGateResult;
  logTag?: string;
}

export async function signInWithPassword(
  opts: SignInWithPasswordOptions
): Promise<{ status: number; body: Record<string, unknown> }> {
  const email = opts.email.trim();
  const password = opts.password;

  if (!email || !password) {
    return { status: 400, body: { error: 'Email and password required.' } };
  }

  const { data, error } = await opts.supabase.auth.signInWithPassword({ email, password });

  if (error || !data.user?.email) {
    // One message for "no such account", "wrong password", and "this account
    // has no password set" alike. Distinguishing them tells an attacker which
    // addresses exist and which are worth guessing at.
    return { status: 400, body: { error: 'That email and password did not match.' } };
  }

  const confirmed = await opts.confirm({ id: data.user.id, email: data.user.email });
  if (!confirmed.ok) {
    await opts.supabase.auth.signOut();
    return { status: confirmed.status, body: { error: confirmed.error } };
  }

  return { status: 200, body: { ok: true } };
}

export interface SetPasswordOptions {
  supabase: PasswordClient;
  password: string;
  /**
   * Re-checked even though the caller is already signed in. A session can
   * outlive the roster row that justified it — someone removed from the
   * roster should not be able to set a password on the way out.
   */
  confirm: (user: { id: string; email: string }) => Promise<OtpGateResult> | OtpGateResult;
  logTag?: string;
}

export async function setPassword(
  opts: SetPasswordOptions
): Promise<{ status: number; body: Record<string, unknown> }> {
  const problem = passwordProblem(opts.password);
  if (problem) return { status: 400, body: { error: problem } };

  const { data: { user }, error: userError } = await opts.supabase.auth.getUser();
  if (userError || !user?.email) {
    return { status: 401, body: { error: 'Sign in before setting a password.' } };
  }

  const confirmed = await opts.confirm({ id: user.id, email: user.email });
  if (!confirmed.ok) {
    return { status: confirmed.status, body: { error: confirmed.error } };
  }

  // Stamped in the same call as the password itself.
  //
  // Supabase gives every user a random encrypted_password at creation, even
  // one who has only ever signed in with a code — so `encrypted_password is
  // not null` says nothing about whether a password was ever *chosen*. This
  // flag is the only honest signal, and it lives on the user rather than in
  // an app's roster table so several apps sharing an auth.users pool all see
  // the same answer.
  const { error } = await opts.supabase.auth.updateUser({
    password: opts.password,
    data: { has_password: true },
  });
  if (error) {
    // Supabase's own rejections are worth surfacing rather than flattening —
    // "this password has been found in a data breach" is actionable, and only
    // it knows that.
    console.error(`[${opts.logTag ?? 'app-auth'}/set-password]`, error.message);
    return { status: 400, body: { error: error.message } };
  }

  return { status: 200, body: { ok: true } };
}


/**
 * Whether this user has ever chosen a password.
 *
 * Only ever answered for a user who is already signed in. Exposing it at the
 * login page — "does this address have a password?" — would be a user
 * enumeration oracle: anyone could probe addresses to learn which exist.
 * A login form that wants to default to the password field should remember
 * that per-browser instead, where the answer reveals nothing to anyone who
 * was not already using that browser.
 */
export function hasPassword(
  user: { user_metadata?: Record<string, unknown> | null } | null | undefined
): boolean {
  return user?.user_metadata?.has_password === true;
}

/**
 * localStorage key for the per-browser hint about which sign-in method last
 * worked here. Shared so both apps agree, and so the value is easy to find
 * and clear. It is a convenience hint only — never a credential, and never
 * trusted for anything but which tab to show first.
 */
export const SIGNIN_HINT_KEY = 'app_auth_signin_hint';
