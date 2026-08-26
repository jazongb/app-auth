// HMAC-signed shared-secret session cookie.
//
// The "one password for the whole group" tier. It carries no identity, and in
// most codebases it is something you are trying to retire — but a cookie
// already issued to real users cannot simply be redefined, because it stays
// live in the field for the length of its TTL. Retiring it means running it
// alongside named sign-in until everyone has moved.
//
// COMPATIBILITY IS LOAD-BEARING. A hand-rolled session cookie tends to pick
// its own payload layout, encoding and timestamp convention, usually without
// documenting any of them, and changing one signs every holder out on the next
// deploy. `sessionCodec()` therefore takes all three explicitly rather than
// imposing a house style, so an existing cookie can be reproduced exactly.
// The variants below are the ones seen in practice; test/ proves each
// byte-identical against a transcription of a real implementation.
//
// Uses Web Crypto only (no Buffer, no node:crypto) so the same code runs in
// Next.js edge middleware, Node route handlers, and non-Next hosts.

export type SigEncoding = 'hex' | 'base64url';

/**
 * Payload layout. An app already issuing cookies uses exactly one of these;
 * picking the wrong one invalidates every cookie in the field.
 *
 *   'prefixed' -> `<prefix>:<expires>`
 *   'bare'     -> `<expires>`
 *   'subject'  -> `<base64url(subject)>.<expires>`
 *
 * Only 'subject' carries anything resembling an identity, and it is a label
 * the issuer chose rather than a verified one — the signature proves the
 * server minted the cookie, nothing about who is holding it.
 */
export type SessionFormat = 'prefixed' | 'bare' | 'subject';

/**
 * What the timestamp in the payload MEANS. Not cosmetic — both conventions are
 * common, hand-rolled implementations pick one without saying so, and reading
 * one as the other silently signs everyone out:
 *
 *   'expires' -> the payload holds the expiry; valid while now < it
 *   'issued'  -> the payload holds the issue time; valid while now - it < ttl
 *
 * A cookie written under 'issued' looks like a long-expired 'expires' cookie,
 * so it fails closed rather than opening a hole — but every holder is logged
 * out on the deploy that gets this wrong.
 */
export type TimestampMeaning = 'expires' | 'issued';

export interface SessionCodecOptions {
  /** Cookie name, e.g. 'app_session'. */
  cookieName: string;
  /** Secret, normally process.env.SESSION_SECRET. */
  secret: string;
  /** Payload layout. Defaults to 'prefixed' when a prefix is given, else 'bare'. */
  format?: SessionFormat;
  /**
   * String prefixed to the payload, e.g. 'app' produces 'app:<expires>'.
   * Only used by the 'prefixed' format. MUST match what the app issues.
   */
  prefix?: string | null;
  /** Signature encoding. MUST match whatever the app already issues. */
  encoding?: SigEncoding;
  /** What the payload timestamp means. MUST match. Defaults to 'expires'. */
  stamp?: TimestampMeaning;
  /** Lifetime in milliseconds. Default 30 days. */
  ttlMs?: number;
}

const DEFAULT_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export interface SessionCodec {
  cookieName: string;
  maxAgeSeconds: number;
  /** `subject` is required by the 'subject' format and ignored by the others. */
  create(subject?: string): Promise<string>;
  /** True when the token is well-formed, correctly signed, and unexpired. */
  verify(token: string | undefined | null): Promise<boolean>;
  /** As verify(), but returns the carried subject ('subject' format) or null. */
  read(token: string | undefined | null): Promise<{ subject: string | null } | null>;
  cookieOptions(secure: boolean): {
    httpOnly: true;
    secure: boolean;
    sameSite: 'lax';
    path: '/';
    maxAge: number;
  };
}

export function sessionCodec(opts: SessionCodecOptions): SessionCodec {
  const { cookieName, secret } = opts;
  const prefix = opts.prefix ?? null;
  const format: SessionFormat = opts.format ?? (prefix === null ? 'bare' : 'prefixed');
  const encoding: SigEncoding = opts.encoding ?? 'hex';
  const stamp: TimestampMeaning = opts.stamp ?? 'expires';
  const ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;

  if (format === 'prefixed' && prefix === null) {
    throw new Error("app-auth: format 'prefixed' requires a prefix");
  }

  async function sign(payload: string): Promise<string> {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
    return encodeSig(new Uint8Array(sig), encoding);
  }

  /** The number written into the payload, per `stamp`. */
  function stampValue(now: number): number {
    return stamp === 'issued' ? now : now + ttlMs;
  }

  /** Whether a payload timestamp is still valid, per `stamp`. */
  function stillValid(ts: number, now: number): boolean {
    return stamp === 'issued' ? now - ts < ttlMs : now < ts;
  }

  function buildPayload(expires: number, subject?: string): string {
    switch (format) {
      case 'prefixed':
        return `${prefix}:${expires}`;
      case 'subject':
        return `${b64urlEncode(new TextEncoder().encode(subject ?? ''))}.${expires}`;
      default:
        return String(expires);
    }
  }

  /** Split a verified payload back into its parts, or null if malformed. */
  function parsePayload(payload: string): { ts: number; subject: string | null } | null {
    switch (format) {
      case 'prefixed': {
        if (!payload.startsWith(`${prefix}:`)) return null;
        return { ts: Number(payload.slice(prefix!.length + 1)), subject: null };
      }
      case 'subject': {
        const dot = payload.lastIndexOf('.');
        if (dot < 0) return null;
        let subject: string;
        try {
          subject = new TextDecoder().decode(b64urlDecode(payload.slice(0, dot)));
        } catch {
          return null;
        }
        return { ts: Number(payload.slice(dot + 1)), subject };
      }
      default:
        return { ts: Number(payload), subject: null };
    }
  }

  async function read(token: string | undefined | null) {
    if (!secret || !token) return null;

    // The signature is always the segment after the FINAL '.', which holds
    // for every format including 'subject' (whose payload contains a '.').
    const lastDot = token.lastIndexOf('.');
    if (lastDot < 0) return null;

    const payload = token.slice(0, lastDot);
    const sig = token.slice(lastDot + 1);
    if (!timingSafeEqual(sig, await sign(payload))) return null;

    const parsed = parsePayload(payload);
    if (!parsed) return null;
    if (!Number.isFinite(parsed.ts) || !stillValid(parsed.ts, Date.now())) return null;

    return { subject: parsed.subject };
  }

  return {
    cookieName,
    maxAgeSeconds: Math.floor(ttlMs / 1000),

    async create(subject?: string) {
      if (format === 'subject' && !subject) {
        throw new Error("app-auth: format 'subject' requires a subject");
      }
      const payload = buildPayload(stampValue(Date.now()), subject);
      return `${payload}.${await sign(payload)}`;
    },

    read,

    async verify(token) {
      return (await read(token)) !== null;
    },

    cookieOptions(secure: boolean) {
      return {
        httpOnly: true as const,
        secure,
        sameSite: 'lax' as const,
        path: '/' as const,
        maxAge: Math.floor(ttlMs / 1000),
      };
    },
  };
}

function encodeSig(bytes: Uint8Array, encoding: SigEncoding): string {
  if (encoding === 'hex') {
    let out = '';
    for (const b of bytes) out += b.toString(16).padStart(2, '0');
    return out;
  }
  return b64urlEncode(bytes);
}

function b64urlEncode(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Length-independent comparison over the two strings.
 *
 * The original implementations used `!==`, which leaks timing. That leak was
 * never the weak link here (the secret is a shared password, and an attacker
 * would need many thousands of samples through Vercel's network jitter), but
 * a constant-time compare costs nothing so there is no reason to keep it.
 */
function timingSafeEqual(a: string, b: string): boolean {
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

/** Constant-time comparison of a submitted password against the expected one. */
export function secretMatches(
  submitted: string | null | undefined,
  expected: string | null | undefined
): boolean {
  if (!submitted || !expected) return false;
  return timingSafeEqual(submitted, expected);
}
