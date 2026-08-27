# app-auth — Session Handoff

*Last updated: 2026-08-26 19:40 PDT (2026-08-27 02:40 UTC)*

### Session 2026-08-26 — Built and adopted across all four FPSC apps

Extracted from four FPSC apps that had hand-rolled auth three divergent ways. Now at
**v0.3.0**, public at `github.com/jazongb/app-auth`, 30 tests, adopted by
fpsc-scheduling, fpsc-caucus-dashboard, fpsc-workplan and Caucus-Groaner.

**Public deliberately.** Vercel's build container has no SSH key and its GitHub App token
scopes to the repo being deployed, so a private git dependency would fail to install on all
four. Verified npm falls back to HTTPS for the `github:` shorthand with
`GIT_SSH_COMMAND=/bin/false npm ci`. Comments were genericised before publishing so the repo
documents no live infrastructure — **keep it that way**; that pass is why it is safe to be public.

**History was rewritten before it went public.** An early commit had real email addresses in
`test/admission.test.mjs`, one of them a colleague's next to `ADMIN_EMAILS`. Force-pushing was
not enough — GitHub keeps unreachable objects retrievable by SHA on a public repo — so the repo
was deleted and recreated from a single clean commit. Verified by cloning fresh and grepping the
whole history.

### Design rules that are load-bearing
- **No app schema.** Apps inject `resolveRoster`; the pipeline is roster → domain → network → deny,
  failing closed. A valid Supabase session is explicitly *not* permission, since apps sharing a
  project share its `auth.users` pool.
- **`canWrite()` vetoes any `network`-admitted principal**, even if the app configures
  `networkRoles: ['member']`. A network match identifies a network, not a person.
- **Membership in the database, elevation in env vars.** An app holding a secret key has a client
  that bypasses every database rule, so a writable `is_admin` column is an escalation path.
- **Functions that accept a Supabase client take narrow structural interfaces** (`OtpClient`,
  `PasswordClient`). supabase-js's client class has protected members, which drag nominal typing
  across the `.d.ts` boundary and fail between structurally identical declarations. Both consumers
  construct their own admin client locally for the same reason — `createAdminClient` is exported
  but effectively unused; the caveat is in the README.

### Before any release
`npm test`. `test/session-compat.test.mjs` is what stands between a refactor and invalidating every
session cookie in the field. Three payload layouts are supported because the deployed apps genuinely
differ — including whether the timestamp is an expiry or an issue time, which is not cosmetic:
reading one as the other fails closed but logs everyone out. `SHIP.md` has the release loop.

### Next
Nothing pending. The clinic guest tier is scaffolded but unwired — `matchNetwork` is a config
callback, so enabling it is config, not a refactor. Adopt in a Three Cedars app when one first
needs auth.
