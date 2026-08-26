// Supabase client factories.
//
// Three clients, three jobs, deliberately never merged:
//
//   middleware  — publishable key + the visitor's session, edge-safe
//   route       — publishable key + the visitor's session, next/headers
//   admin       — secret key, NO session, bypasses RLS
//
// The split matters most when a project leaves RLS off and enforces access in
// the application layer, which is a common shape for small internal tools. In
// that setup the secret key is entirely unrestricted, so it must never be
// handed a user session, and the session clients must never be used to read
// tables that assume the secret key for access. Keeping middleware and route
// separate is a Next.js constraint — middleware cannot import next/headers.

import { createServerClient } from '@supabase/ssr';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';

export interface SupabaseEnv {
  url: string;
  publishableKey: string;
}

export interface CookieAdapter {
  getAll(): { name: string; value: string }[];
  setAll(
    cookies: { name: string; value: string; options?: Record<string, unknown> }[]
  ): void;
}

/** Session-scoped client over any cookie store. */
export function createSessionClient(env: SupabaseEnv, cookies: CookieAdapter) {
  return createServerClient(env.url, env.publishableKey, {
    cookies: {
      getAll: () => cookies.getAll(),
      setAll: toSet => {
        try {
          cookies.setAll(toSet);
        } catch {
          // Called from a Server Component, which cannot set cookies. Safe to
          // ignore as long as middleware also refreshes the session.
        }
      },
    },
  });
}

/**
 * Edge-middleware client: reads the session off the request, writes any
 * refreshed session onto the response.
 */
export function createMiddlewareClient(
  env: SupabaseEnv,
  req: { cookies: { getAll(): { name: string; value: string }[]; set(name: string, value: string): void } },
  res: { cookies: { set(name: string, value: string, options?: Record<string, unknown>): void } }
) {
  return createSessionClient(env, {
    getAll: () => req.cookies.getAll(),
    setAll: toSet => {
      toSet.forEach(({ name, value }) => req.cookies.set(name, value));
      toSet.forEach(({ name, value, options }) => res.cookies.set(name, value, options));
    },
  });
}

/**
 * Secret-key client. Bypasses RLS entirely — server-only, never import from
 * a 'use client' component, and never give it a user session.
 */
export function createAdminClient(url: string, secretKey: string): SupabaseClient {
  if (!url || !secretKey) {
    throw new Error('app-auth: Supabase URL / secret key not configured');
  }
  return createClient(url, secretKey, { auth: { persistSession: false } });
}

/** Read the Supabase env pair, failing loudly rather than at request time. */
export function supabaseEnv(
  env: Record<string, string | undefined> = process.env
): SupabaseEnv {
  const url = env.NEXT_PUBLIC_SUPABASE_URL ?? env.SUPABASE_URL;
  const publishableKey = env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  if (!url) throw new Error('app-auth: NEXT_PUBLIC_SUPABASE_URL is not set');
  if (!publishableKey) {
    throw new Error('app-auth: NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY is not set');
  }
  return { url, publishableKey };
}
