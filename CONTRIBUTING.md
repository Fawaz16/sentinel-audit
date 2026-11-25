# Contributing

This is a teaching lab, so the bar for a contribution is a little unusual: **does
it help someone understand the problem?**

## Most wanted

**Attacks that get past `HARDENED` mode.** A lab that only demonstrates attacks
it already blocks is not teaching much. If you find a manifest shape, encoding,
or tool-use path that survives the guard, that is the single most valuable thing
you can contribute. Open an issue or a PR with a reproducing test.

Also welcome:

- **New attack vectors** that illustrate a *different class* of problem —
  semantic injection with no encoding at all, split payloads, homoglyphs. See
  [docs/LAB-EXERCISES.md §11](docs/LAB-EXERCISES.md#11-write-a-third-attack-vector).
- **Clearer explanations.** If a paragraph in the README or docs made you reread
  it, that is a bug. Fixes to it are as valuable as code.
- **Tests for the gaps** listed in
  [docs/LAB-EXERCISES.md §10](docs/LAB-EXERCISES.md#10-find-a-gap-the-guard-still-has)
  — replay protection especially.
- **Setup friction.** Anything that tripped you up between `git clone` and the
  first 🎯.

## Before you open a PR

```bash
git config core.hooksPath .githooks   # once per clone: blocks committing secrets
npm run verify                        # typecheck + 62 tests
```

Both must pass. `npm run build` additionally needs a filled-in `.env.local`, so
CI does not run it.

## The invariants are not up for casual revision

Six constraints in [README.md](README.md#design-invariants) define what this
project is arguing. A PR that breaks one is not automatically wrong, but it needs
to say why in the description:

1. No `service_role` key in application code
2. Prompt rules are never security boundaries
3. Taint always drives tool removal
4. No `eval()`
5. Token discipline (prompt caching, compact JSON, `max_tokens: 350`)
6. The audit log is append-only

In particular: **a defence implemented by adding text to a system prompt will be
declined.** That is the thing this repo exists to argue against. Put it in
`crossDomainGuard.ts` or in Postgres.

## House style

- **TypeScript, `strict`, no `any`** in new code.
- **No new runtime dependencies** without a reason in the PR description. The
  cipher and key layers depend on `node:crypto` alone, which is why they run
  under plain `node`, under Next.js, and in tests without a build step.
- **Comments explain *why*.** The code says what it does; a comment earns its
  place by saying why it is that way, or what breaks otherwise.
- **Every security claim gets a test.** If you add a control, add the assertion
  that it holds — and ideally one that fails when you remove it.
- **Keep `scripts/` and `src/lib/` runnable by bare `node`.** That means
  explicit `.ts` extensions on relative imports and no bundler-only features.

## Reporting something

- A bypass of the guard → public issue or PR. That is a feature request.
- A flaw that could harm someone *running* this repo → private report. See
  [SECURITY.md](SECURITY.md).

## Project layout

See [README.md § Project layout](README.md#project-layout). Shortest path in:
`src/lib/crossDomainGuard.ts`, then `src/app/api/simulate/route.ts` step 3, then
`tests/crossDomainGuard.test.ts`.
