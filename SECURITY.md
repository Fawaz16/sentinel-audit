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
- **Do not deploy this publicly.** There is no authentication on the simulate
  endpoint; anyone who can reach it can run the attacks and read the vault
  contents from the response. It is a localhost lab.

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

## Out of scope

- The intentionally permissive RLS policies in `supabase/schema.sql`.
- The lack of authentication on `/api/simulate`.
- The fictional credentials committed in `supabase/schema.sql` and `.env.example`.
- That the simulated adversary succeeds in `VULNERABLE` mode. That is the demo.
- That a Morse key is not encryption. It is documented as an encoding in
  `docs/BUILD-YOUR-OWN-MORSE-KEY.md`.
