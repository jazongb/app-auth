# @jaron/app-auth

Shared auth core for Next.js apps. Supabase email-code sign-in, shared-secret
sessions, and one admission pipeline that every app resolves identity through.

Consumed as a git dependency — there is no registry and no publish step.

```json
"@jaron/app-auth": "github:jazongb/app-auth#v0.2.0"
```

npm runs `prepare` on git installs, so `dist/` is built at install time. A
release is `npm version patch && git push --tags`.

Consumers are pinned to a tag deliberately: a shared auth package that floats
under four live apps is how one bad commit signs out every user at once.
See [SHIP.md](SHIP.md) for the first-time setup and the release loop.

**`createAdminClient` caveat.** Both current consumers construct their
secret-key client locally instead of using it, because supabase-js's client
class has protected members — so a client built inside this package is not
assignable to a `SupabaseClient` annotation in the app. Functions here that
*accept* a client take a narrow structural interface (`OtpClient`) to sidestep
that. If you hit `Two different types with this name exist`, this is why:
construct the client in the app.

---

## What this package does and does not know

It knows how to verify a session, check an allowlist, run an OTP exchange, and
decide what roles a request carries.

It knows **nothing** about any app's schema. No table names, no Supabase
project, no roster shape. Apps inject a `resolveRoster` callback, which is the
entire reason two unrelated apps — different Supabase projects, different
schemas, different ideas of what a member even is — can share this code
without either constraining the other.

---

## The admission pipeline

Every app answers "who is this and what may they do?" the same way, in the
same order, failing closed:

| # | Step | Grants | Source |
|---|---|---|---|
| 1 | **Roster** — the app looks the verified email up in its own tables | whatever the app returns | `roster` |
| 2 | **Domain** — the email's domain is on a trusted-domain env allowlist | `member` (configurable) | `domain` |
| 3 | **Network** — the request came from a trusted network | `guest`, capped | `network` |
| 4 | **Deny** | nothing | `none` |

Admin is granted on top of step 1 from an env allowlist, and is the only role
this package grants directly.

```ts
const principal = await admit(user, {
  resolveRoster: async u => {
    const row = await db.from('feeds').select('name').eq('email', u.email).maybeSingle();
    return row.data ? { roles: ['physician', 'member'], name: row.data.name } : null;
  },
  adminEmailsEnv: 'ADMIN_EMAILS',
  trustedDomainsEnv: 'TRUSTED_DOMAINS',
});

if (!requireWrite(principal).ok) return NextResponse.json({ error: '...' }, { status: 403 });
```

**Being signed in is not permission to be anywhere.** Apps sharing a Supabase
project also share its `auth.users` pool, so a perfectly valid session may
belong to a different app's user entirely. Step 4 is the default for a reason.

---

## Where privileges live

| What | Where | Why |
|---|---|---|
| Membership (who exists) | database | changes often, managed through an admin UI |
| Elevation (who is admin) | env var | changes rarely, and granting it needs deploy access |

An app holding a Supabase secret key has, by construction, a client that
bypasses every database rule. If it also enforces access in the application
layer rather than through RLS, any route able to write an `is_admin` column
becomes a privilege-escalation path. An env var has no such path inside the app
at all. The cost is that changing it needs a redeploy — Vercel bakes env values
into a deployment, server-side vars included. That friction is the point.

---

## The guest / network tier

`matchNetwork` is **scaffolded and unwired**. Supply a matcher and unauthenticated
visitors from a trusted network are admitted as `guest`.

Before enabling it, read what it actually asserts: a network match identifies a
*network*, not a person. Everyone on that wifi matches, including whoever is
sitting in the waiting area, and a dynamic ISP address can stop matching
without warning. `x-forwarded-for` is also a header, forgeable by anything between the
client and the trusted proxy.

So the package enforces the cap rather than trusting the caller: `canWrite()`
returns false for any `network`-admitted principal *and* for anything holding
`guest`, even if the app configures `networkRoles: ['member']`. Treat it as
"skip the sign-in wall for read-only convenience", never as identity.

---

## Sessions

`sessionCodec()` is the legacy shared-password tier — one password for a whole
group, carrying no identity. It exists so that tier can be *retired gradually*
rather than in one deploy that signs everyone out.

**Compatibility is load-bearing.** A cookie already issued stays live for the
length of its TTL, so the layout, encoding and timestamp meaning must match
exactly what the app already emits. Get one wrong and every holder is signed
out on the next deploy.

| Option | Values |
|---|---|
| `format` | `prefixed` — `<prefix>:<expires>` · `bare` — `<expires>` · `subject` — `<b64url(subject)>.<expires>` |
| `encoding` | `hex` · `base64url` |
| `stamp` | `expires` — valid while `now < ts` · `issued` — valid while `now - ts < ttl` |

`stamp` is the one that bites: both conventions are common and hand-rolled code
rarely says which it uses. Reading an `issued` cookie as an `expires` one fails
closed rather than open, but it still logs everyone out.

`test/session-compat.test.mjs` proves each layout byte-identical against a
transcription of a real implementation. When adopting this in an app,
transcribe its session code the same way and add a case. Run the tests before
changing anything in `session.ts`.

Uses Web Crypto only — no `Buffer`, no `node:crypto` — so the same code runs in
edge middleware, Node route handlers, and non-Next hosts.

---

## Passwords

Optional, and layered on top of the code flow rather than replacing it. A
password manager fills a password instantly where a code costs an inbox
round-trip; that ergonomic gap is the entire reason this exists.

`signInWithPassword()` and `setPassword()` both run the **same admission gate**
the code path runs, against the user Supabase actually authenticated — never
the address the client posted — and sign the user out on refusal. A password
proves possession of a credential, not membership: in a shared `auth.users`
pool it may belong to a different app's user entirely.

Length is the only rule (`MIN_PASSWORD_LENGTH`, 12). Composition rules push
people toward predictable substitutions and away from password managers. Turn
on Supabase's leaked-password protection instead — checking the actual password
against known breaches beats counting character classes.

**There is no password-reset email, deliberately.** It would be a second
code-to-the-same-inbox mechanism with no capability the sign-in code lacks, and
every extra Supabase template is another default that ships with a URL in it —
another place the no-links rule can silently regress. Forgetting a password is
handled by signing in with a code and setting a new one; surface that as
"Forgot your password?" on the login form so it is findable.

---

## OTP: two rules that cost real debugging

1. **Gate before sending.** The allowlist check runs before Supabase Auth is
   touched, and `shouldCreateUser` defaults to `false`. Otherwise a scripted
   address can mint an auth user and trigger a real email through whatever
   SMTP sender the project is configured with.

2. **Never ship a URL in the email.** Corporate mail scanners fetch every URL
   in a message. Fetching a Supabase magic link consumes the single-use token,
   and the numeric code is the *same token record* — so it is dead before the
   recipient reads it. Templates must render only `{{ .Token }}`.
   `emailRedirectTo` is omitted by default.

`verifyCode` re-checks the address Supabase actually authenticated, not the one
the client posted, and signs the user out on refusal so no usable session is
left behind.

---

## Development

```bash
npm install
npm run build
npm test
```
