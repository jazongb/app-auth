// Email one-time-code sign-in.
//
// Two hard-won rules are baked in here so no app has to rediscover them:
//
// 1. GATE BEFORE SENDING. The allowlist/roster check runs before Supabase
//    Auth is touched at all. Otherwise an arbitrary or scripted address can
//    mint an auth user and trigger a real email through whatever SMTP sender
//    the project uses. `shouldCreateUser` defaults to false for the same
//    reason.
//
// 2. NEVER SHIP A URL IN THE EMAIL. Corporate mail scanners (Safe Links and
//    friends) fetch every URL in a message. Fetching a Supabase magic link
//    consumes the single-use token, so the recipient's code is already dead
//    by the time they read it — and the numeric code is the SAME token
//    record, so it dies too. The email template must render only
//    `{{ .Token }}`. `emailRedirectTo` is therefore omitted by default; pass
//    it only if you have confirmed the template contains no link.
//
// Rule 2 cost real debugging to find. Do not reintroduce a link.

// Takes the narrowest client shape it actually uses rather than the full
// SupabaseClient class. Two reasons: supabase-js's client has protected
// members, so passing the class across a .d.ts boundary drags in nominal
// typing and fails between structurally identical declarations; and this
// keeps the package from pinning itself to one supabase-js version's class
// internals when all it needs is three auth calls.
export interface OtpClient {
  auth: {
    signInWithOtp(params: {
      email: string;
      options?: { shouldCreateUser?: boolean; emailRedirectTo?: string };
    }): Promise<{ error: { message: string } | null }>;
    verifyOtp(params: { email: string; token: string; type: 'email' }): Promise<{
      data: { user: { id: string; email?: string | null } | null };
      error: { message: string } | null;
    }>;
    signOut(): Promise<unknown>;
  };
}

export type OtpGateResult =
  | { ok: true }
  | { ok: false; status: number; error: string };

export interface RequestCodeOptions {
  supabase: OtpClient;
  email: string;
  /** Runs BEFORE Supabase is contacted. Return not-ok to refuse the send. */
  gate: (email: string) => Promise<OtpGateResult> | OtpGateResult;
  /** Leave false unless the address is allowed to create a new auth user. */
  shouldCreateUser?: boolean;
  /** Only set this if the email template is confirmed link-free. See above. */
  emailRedirectTo?: string;
  /** Label for server-side logs. */
  logTag?: string;
}

export async function requestCode(
  opts: RequestCodeOptions
): Promise<{ status: number; body: Record<string, unknown> }> {
  const email = opts.email.trim();
  if (!email) {
    return { status: 400, body: { error: 'Email required.' } };
  }

  const gated = await opts.gate(email);
  if (!gated.ok) {
    return { status: gated.status, body: { error: gated.error } };
  }

  const { error } = await opts.supabase.auth.signInWithOtp({
    email,
    options: {
      shouldCreateUser: opts.shouldCreateUser ?? false,
      ...(opts.emailRedirectTo ? { emailRedirectTo: opts.emailRedirectTo } : {}),
    },
  });

  if (error) {
    console.error(`[${opts.logTag ?? 'app-auth'}/request-code]`, error.message);
    return { status: 500, body: { error: 'Could not send the code. Try again.' } };
  }

  return { status: 200, body: { ok: true } };
}

export interface VerifyCodeOptions {
  supabase: OtpClient;
  email: string;
  token: string;
  /**
   * Re-check the address Supabase actually authenticated — NOT the one the
   * client posted. The request-code gate is not sufficient on its own: a
   * valid code belonging to a different, non-allowlisted account could
   * otherwise be redeemed against this route.
   */
  confirm: (user: { id: string; email: string }) => Promise<OtpGateResult> | OtpGateResult;
}

export async function verifyCode(
  opts: VerifyCodeOptions
): Promise<{ status: number; body: Record<string, unknown> }> {
  const email = opts.email.trim();
  const token = opts.token.trim();
  if (!email || !token) {
    return { status: 400, body: { error: 'Email and code required.' } };
  }

  const { data, error } = await opts.supabase.auth.verifyOtp({
    email,
    token,
    type: 'email',
  });

  if (error || !data.user?.email) {
    return { status: 400, body: { error: 'That code is invalid or has expired.' } };
  }

  const confirmed = await opts.confirm({ id: data.user.id, email: data.user.email });
  if (!confirmed.ok) {
    // Do not leave a usable session behind on a refused sign-in.
    await opts.supabase.auth.signOut();
    return { status: confirmed.status, body: { error: confirmed.error } };
  }

  return { status: 200, body: { ok: true } };
}

/** Convenience gates. */
export const GATE_OK: OtpGateResult = { ok: true };

export function refuse(error: string, status = 403): OtpGateResult {
  return { ok: false, status, error };
}
