// Env-var allowlists.
//
// Privilege elevation lives in the environment, not the database. That is the
// convention for every app using this package:
//
//   membership  -> database   (changes often, managed through an admin UI,
//                              and is only ever "which humans exist")
//   elevation   -> env var    (changes ~twice a year, and granting it
//                              requires deploy access — a real second factor)
//
// The reason this matters more than it looks: an app that holds a Supabase
// secret key and enforces access in the application layer has, by
// construction, a client that bypasses every database rule. In that setup any
// route able to write an "is_admin" column is a privilege-escalation path. An
// env var has no such path inside the app at all. The cost is that changing it
// needs a redeploy (Vercel bakes env values into a deployment, server-side
// vars included) — that friction is the point, not a limitation to design
// around.

/** Parse a comma-separated env allowlist into lowercased, trimmed entries. */
export function parseList(raw: string | undefined | null): string[] {
  return (raw ?? '')
    .split(',')
    .map(e => e.trim().toLowerCase())
    .filter(Boolean);
}

/** True when `value` appears in the comma-separated env var named `envVar`. */
export function isListed(
  value: string | null | undefined,
  envVar: string,
  env: Record<string, string | undefined> = process.env
): boolean {
  if (!value) return false;
  return parseList(env[envVar]).includes(value.toLowerCase());
}

/**
 * True when `email`'s domain appears in the comma-separated env var.
 * Entries may be written with or without a leading '@'.
 */
export function isDomainListed(
  email: string | null | undefined,
  envVar: string,
  env: Record<string, string | undefined> = process.env
): boolean {
  if (!email) return false;
  const at = email.lastIndexOf('@');
  if (at < 0) return false;
  const domain = email.slice(at + 1).toLowerCase();
  return parseList(env[envVar])
    .map(d => (d.startsWith('@') ? d.slice(1) : d))
    .includes(domain);
}
