# Hosting / stack quirks worth knowing before you conclude something's a bug

Lessons from real audits — read this when a result looks surprising, before writing it up as a
finding. A lot of "weird" behavior here is a platform doing its job, not a vulnerability.

## Vercel

- A WAF/bot-mitigation layer sits in front of the app. Once it starts blocking a scanner's
  requests, responses often come back as `403` with `x-vercel-mitigated: deny`. This is the
  platform protecting the site — not a finding, and definitely not evidence the path underneath
  is sensitive (a totally harmless path can get the same 403 if its name looks scanner-shaped,
  e.g. `wp-config.php.bak` on a site that was never WordPress).
- The same mitigation is why `nuclei` scans against Vercel-hosted sites can silently stall at
  ~40-50% progress with `Matched: 0, Errors: <climbing>` — it's not "no vulnerabilities found",
  it's "the WAF started dropping our requests and nuclei gave up on the host." Always run with
  `-mhe 0` and a modest `-rate-limit` (8-20/sec), and confirm the final `Requests: X/Y` line
  actually reached ~99-100% before trusting a zero-findings result.

## Beget (RU shared hosting)

- Requests to scanner-shaped paths (`/wp-login.php`, `/admin`, etc.) on non-WordPress sites can
  get intercepted by a bot-challenge: a tiny HTML page with an inline script that sets a
  `beget=begetok` cookie and reloads. That's Beget's own anti-bot layer, not the application —
  don't report it as "fake WordPress login page found," it just means the real site isn't
  WordPress and the hosting platform is filtering bot-looking requests.
- `server_tokens off` (hiding the nginx version in the `Server` header) usually can't be set by
  the site owner on shared hosting — it requires the hosting provider to change it at the
  front-end nginx layer. If you flag a disclosed nginx version as a finding on Beget or similar
  shared hosts, say explicitly that the fix may require a support ticket to the host, not a code
  change.

## Payload CMS

- `auth.maxLoginAttempts` / `lockTime` lock out failed logins **per user document** — the
  counter lives on the actual user record. A brute-force test against an email that doesn't exist
  in the database will never trigger a lockout, no matter how many attempts you send, because
  there's no record to increment. This is not a bug — locking a nonexistent account makes no
  sense, and avoiding it also prevents an attacker from using lockout timing as a way to enumerate
  which emails have real accounts. If you only have a fake test email, say so explicitly and ask
  for a real disposable account before concluding brute-force protection is missing.
- The admin panel (`/admin`) and a public-facing account login often authenticate against the
  *same* endpoint (e.g. `/api/users/login`) if they're the same collection with role-based access
  underneath. Worth checking explicitly (watch the network tab while logging into `/admin`) —
  if true, any auth weakness on the "customer" login is also a weakness on the admin login, which
  changes the severity a lot.
- `/api/access` is a public, unauthenticated endpoint by design — it tells the client what the
  *current* (possibly anonymous) user can do on every collection/field. Fetching it isn't itself
  a vulnerability, but reading it is a fast way to see which collections/fields anonymous
  `create`/`read`/`update` access is enabled on, which is exactly where to focus mass-assignment
  testing next.
- A field appearing in `/api/access` with anonymous `create: true` doesn't automatically mean an
  anonymous request can actually set it to an attacker-chosen value — a `beforeChange` hook can
  silently strip or override it server-side regardless of what the access-control layer allows at
  the request level. Don't declare a mass-assignment vulnerability confirmed just because a field
  is listed as anonymously-writable; you have to check whether the value actually landed (which
  usually needs the owner to check their DB/admin panel, since anonymous read access on sensitive
  fields is normally — correctly — locked down).

## Supabase

- The anon/public key is *meant* to be public — it ships in client-side JS by design. It is not a
  secret and finding it is not itself a finding. The real question is what the Row Level Security
  (RLS) policies on each table allow that key to do: test with
  `curl -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" "$PROJECT_URL/rest/v1/<table>?select=*"`
  against likely table names, and see whether unauthenticated reads/writes succeed on tables that
  should be private.
- If a site's JS bundle references a `*.supabase.co` project, verify it's still live before
  testing against it: `curl -s "https://dns.google/resolve?name=<project-ref>.supabase.co&type=A"`
  — `"Status":3` means NXDOMAIN, i.e. the project was deleted or the reference is stale (common
  after a migration to a different backend). A live browser session with network-request logging
  will show you what the frontend *actually* calls at runtime, which can differ from what's
  hardcoded in an old bundle — trust the live network traffic over grepping the JS.

## Generic SPA / front-controller pattern

- Many setups (React/Vue SPA fallback routing, PHP front controllers) return `HTTP 200` with the
  homepage or a client-rendered shell for *any* unmatched path, instead of a real `404`. Always
  fingerprint this first (`scripts/recon.sh` does it automatically) — otherwise every "exposed
  path" check becomes a false positive, since `phpmyadmin`, `backup.zip`, and
  `totally-made-up-xyz123` will all return the identical `200` and same byte size.
