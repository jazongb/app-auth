# Adopting and releasing

## Adding this to an app

```bash
npm install "github:jazongb/app-auth#v0.1.0"
```

Pin a tag, not a branch. npm runs `prepare` on git installs, so `dist/` is
built at install time — which is also why `dist/` is gitignored here.

Then build the app and run its tests before committing the lockfile.

**If the app already issues its own session cookies**, transcribe that
implementation into `test/session-compat.test.mjs` as a new case and make it
pass *before* swapping anything over. That test is the only thing standing
between adoption and signing every existing holder out on the next deploy.
Check all three of `format`, `encoding` and `stamp` — the last one especially,
since hand-rolled code rarely records whether its timestamp is an expiry or an
issue time.

---

## Releasing a change later

```bash
cd ~/Developer/General/app-auth && npm test && npm version patch && git push && git push --tags
```

Then bump each consumer's tag and redeploy it. Consumers are pinned to a tag on
purpose: a shared auth package that floats under several live apps is how one
bad commit signs out every user at once.

**Run `npm test` before every release.** `test/session-compat.test.mjs` is the
thing standing between a refactor and every session cookie in the field being
invalidated on the next deploy.
