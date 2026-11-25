# Security policy

## What this project is

`captain-foxv1` is a **security research and teaching lab**. It deliberately
contains working demonstrations of indirect prompt injection, covert
agent-to-agent channels, and data exfiltration, so that the defences against
them can be shown working.

Everything hostile in this repository is confined to the project's own mock
tools and tables:

- The "customs vault" secrets are invented. See `supabase/schema.sql`.
- The "attacker inbox" is a Postgres table named `attacker_sink`. The email tool
  inserts a row. There is no SMTP client and no outbound network path.
- The default adversary is a local `switch` statement in
  `src/app/api/simulate/route.ts`. It can only call this lab's four mock tools.
- The attack techniques shown are publicly documented. The defences are the
  contribution.

## Running it safely

- **Use a throwaway Supabase project.** The RLS policies say `USING (true)` on
  purpose, because the demo needs something stealable. Never point this at a
  database you care about.
- **Never add a `SUPABASE_SERVICE_ROLE_KEY`.** The project is built around the
  anon key plus RLS, and a privileged key would both break the lesson and widen
  the blast radius of a misconfiguration.
- **Do not reuse the committed example secrets.** Everything in `.env.example`
  is a public placeholder. Run `npm run forge -- secrets` for fresh values.
- **Do not deploy this publicly.** There is no authentication on
  `/api/simulate`; anyone who can reach it can run the attacks, read the vault
  contents out of the JSON response, and spend your Anthropic credits. It is a
  localhost lab. `npm run dev` therefore binds `127.0.0.1` explicitly, because
  Next's default also serves your LAN. `npm run dev:lan` opts back in; only use
  it on a network you trust.
- **Use a high-entropy `AGENT_AUTH_SECRET`.** The response returns each manifest
  together with its HMAC, which is a verifiable (plaintext, MAC) pair — an
  offline cracking oracle. That is acceptable for a teaching UI only while the
  secret has real entropy, so the route refuses to run on a placeholder or on
  anything under 24 characters. Run `npm run forge -- secrets`.
- **Enable the commit hook** (`git config core.hooksPath .githooks`) so an env
  file or a live key cannot be committed by accident.

## Reporting a vulnerability

Two different things get reported here, and they are handled differently.

### A bypass of the guard — please open a public issue or PR

If you find a way past `HARDENED` mode, that is a **feature request, not a
vulnerability disclosure**. The lab exists to be attacked, and a bypass is the
most valuable contribution anyone can make to it. Open an issue or a PR with a
reproducing test in `tests/crossDomainGuard.test.ts`.

Examples: a manifest shape that is not tainted but should be; a covert channel
that survives schema stripping; a path that reaches a locked tool.

### A vulnerability in the lab *as software* — please report privately

If you find a flaw that could harm someone running this repo — not a flaw in the
simulated scenario — report it privately via GitHub's **Security → Report a
vulnerability** (private advisory), or to the repository owner.

Examples: a path that makes a real outbound network request; something that
could read or exfiltrate data outside the `captain_fox` schema; a way for a
hostile manifest to achieve code execution; a dependency advisory that actually
affects this code.

Please include the version or commit, reproduction steps, and what an attacker
would gain. Expect an initial response within a week.

## Known and accepted

These are deliberate properties of a teaching lab, documented rather than fixed.
If one of them matters to you, the mitigation is noted.

| Property | Why it is this way | Mitigation |
|---|---|---|
| `/api/simulate` is unauthenticated | The lab is a single-user localhost tool; auth would add setup friction for no teaching value | Bound to `127.0.0.1` by default |
| The response returns the manifest and its HMAC | Showing the signature is pedagogically useful — it is what makes "identity ≠ integrity" concrete | Enforced minimum secret entropy |
| RLS policies are `USING (true)` | The exfiltration demo needs readable secrets | Use a throwaway project; tables live in `captain_fox`, not `public` |
| `INVISIBLE_UNICODE` is a deny-list with known gaps | It is a detector, not the boundary; the schema allow-list and Biba lockout are | Exercise 6 in `docs/LAB-EXERCISES.md` walks through it |
| No replay protection on manifests | Out of scope for the current guard | Exercise 10 asks you to add it |

## Out of scope

- The intentionally permissive RLS policies in `supabase/schema.sql`.
- The lack of authentication on `/api/simulate`.
- The fictional credentials committed in `supabase/schema.sql` and `.env.example`.
- That the simulated adversary succeeds in `VULNERABLE` mode. That is the demo.
- That a Morse key is not encryption. It is documented as an encoding in
  `docs/BUILD-YOUR-OWN-MORSE-KEY.md`.
