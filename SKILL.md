---
name: site-security-audit
description: Runs a hands-on security audit of a live website — headers, exposed config/backup files, an automated nuclei scan, CORS misconfiguration, cookie flags, open redirects, file-upload handling, live probing of login/registration forms for SQLi/NoSQLi/XSS and brute-force protection, and business-logic checks (mass assignment, price manipulation, IDOR) on custom APIs. Use this whenever the user asks to check a site for vulnerabilities, "проверь сайт на уязвимости", "пентест", "просканируй сайт", "есть ли дыры в безопасности", or wants a security review of their own website, web app, or API before/after a fix. Always confirms authorization before any active testing — refuses to actively scan a site the user doesn't own or isn't authorized to test. Also covers re-verifying fixes after the user reports deploying them, and drafting a fix-it prompt for a Claude Code session.
---

# Site Security Audit

A practical, hands-on vulnerability check for a real website — not a report generated from
general knowledge. Every claim in the final report must be backed by an actual request/response
you ran, not a guess about what a site "probably" has.

## Step 0: Authorization — never skip this

Before running anything beyond a plain page load, confirm who owns the target. Active security
testing on a site without authorization is illegal (unauthorized access laws) and against policy.

Use AskUserQuestion (or just ask directly in chat) with something like: "Это твой сайт, или у
тебя есть письменное разрешение владельца на тестирование?" Three outcomes:

- **Own site / has written authorization** → proceed with the full workflow below.
- **Third-party site, no confirmed authorization** → refuse active testing (no injection
  payloads, no brute-force attempts, no scanner). You can still do fully passive checks a normal
  browser visit would do (response headers, SSL cert dates) if the user just wants public info,
  but say plainly that a real vulnerability check needs the owner's permission.
- **"Just curious"** → same as above, decline active testing.

Re-ask if the user brings a *new* domain mid-conversation — ownership doesn't carry over from a
previous site just because the same person is asking.

## Step 1-2: Recon, exposed paths, CORS, cookies

Run the bundled script to cover this mechanically instead of hand-typing the same curl loop
every time:

```bash
scripts/recon.sh https://target-site.com
```

It dumps headers, checks which of the standard security headers are missing
(`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`,
`Permissions-Policy`, `Referrer-Policy` — missing ones are very often the single most impactful
cheap fix on an otherwise-solid site), pulls the SSL cert dates, confirms the HTTP→HTTPS redirect,
fingerprints whether the site has a real 404 or returns `200` for everything (critical context —
see below), probes the common sensitive-path list from `references/payloads.md`, checks whether
`Access-Control-Allow-Origin` reflects an arbitrary `Origin` header (CORS misconfiguration), and
checks `Set-Cookie` headers for missing `Secure`/`HttpOnly`/`SameSite` flags.

Read its output, don't just skim for red flags — several of its checks are judgment calls the
script flags but can't resolve on its own:

- **Fallback-page fingerprint matters most.** Some sites (misconfigured SPA fallback, PHP front
  controllers) return `200` with the homepage for *any* unmatched path. If that's the pattern, a
  `200` on a "sensitive" path is meaningless — the script compares byte size against the fallback
  automatically and flags matches, but you still need to eyeball anything that returned `200`
  with a *different* size, since that's the one that's actually real content.
- A `403` with `x-vercel-mitigated: deny`, or a bot-challenge page (e.g. Beget's `beget=begetok`
  cookie trick), means the *hosting platform* is blocking scanner-shaped requests — that's a
  positive signal about the hosting layer, not a finding to report as a vuln. See
  `references/hosting-quirks.md` for more platform-specific behavior like this before writing
  something up as a bug.
- CORS reflecting an arbitrary origin is only a real vulnerability if the response also carries
  `Access-Control-Allow-Credentials: true` (otherwise there's no session/cookie to steal
  cross-origin) — check both together before calling it critical.
- The script only checks cookies set on the homepage. Re-run the cookie check by hand
  (`curl -sI` on the actual login/session endpoint) if the homepage doesn't set any — session
  cookies are usually only issued after authentication.

From the headers and page source, also identify the stack (framework/CMS, hosting — e.g.
Next.js/Payload/Vercel vs nginx+custom PHP vs WordPress vs static). This changes what's worth
probing later (WordPress → wpscan-style paths matter; a Payload/Next app → look at its REST/GraphQL
conventions instead).

## Step 3: Automated scan (nuclei)

```bash
command -v nuclei
```

If missing and the user wants a deeper automated pass, ask before installing (`brew install
nuclei` — new software, needs explicit permission). Then:

```bash
nuclei -update-templates
nuclei -u "https://target" -severity low,medium,high,critical -rate-limit 8 -timeout 10 -mhe 0 -stats -silent -o results.txt
```

Run this **in the background** — with thousands of templates it can take 15–25 minutes even at a
modest rate. Two things that will bite you if skipped:

- `-mhe 0` disables nuclei's default "give up on a host after ~30 errors" behavior. Without it, a
  WAF that starts blocking requests partway through (very common — e.g. Vercel's bot mitigation)
  causes the scan to silently abort at ~40-50% with `Matched: 0`, which looks like "no
  vulnerabilities" but actually means "we stopped looking." Always check the final `Requests: X/Y`
  line hit ~99-100% before trusting a zero-findings result.
- Keep `-rate-limit` modest (8-20/sec). Blasting a small site at full speed is indistinguishable
  from a DoS attempt and is more likely to trip the WAF and abort the scan than to find anything.

## Step 4: Form and auth testing (only with confirmed authorization)

Find login/registration forms with the browser tools first (to see the real fields and flow),
then test the underlying API directly with `curl` — bypassing client-side HTML5 validation
(`type="email"` etc. will silently block malformed input at the browser layer and give you a
false sense of security if you only test through the UI).

Try the SQLi / NoSQLi / XSS payloads from `references/payloads.md` against the login endpoint,
checking that every response stays a generic "invalid credentials" with no SQL error, no timing
tell, and no reflection.

**Brute-force / lockout test** — send 15-25 rapid failed attempts and watch for a lockout
message or HTTP 429 appearing partway through. Important nuance: many auth systems (Payload CMS's
built-in `maxLoginAttempts` included) track failed attempts **on the user record itself** — a
nonexistent email has no record to increment, so it will *never* lock out no matter how many
attempts you send. That's not a bug, it's usually intentional (prevents attackers from locking out
real accounts via someone else's email, and avoids a lockout-based user-enumeration side channel).
If you only have a fake email to test with, say so explicitly in the report and ask the user for
a real (disposable) test account before concluding brute-force protection is missing.

**Mass-assignment test** on registration/creation endpoints — try slipping in the extra fields
listed in `references/payloads.md` (`role`, `isAdmin`, `wallet`, `price`, `verified`, ...). If a
record gets created, check whether the sensitive field is actually reflected/echoed — an API can
validly omit a field from the response because the anonymous caller lacks *read* access to it,
which doesn't prove the value wasn't set. Say this explicitly rather than declaring victory or
failure from the response alone; recommend the user check their DB/admin panel for ground truth.

Always label test data unmistakably (e.g. name `"SECTEST DoNotUse"`) and tell the user afterward
exactly which record(s) to delete — collection/table, id, and identifying field. If no delete
endpoint is reachable anonymously, say that's actually a good sign (no IDOR on delete) but that
manual cleanup is still needed.

**Open redirect** — on any parameter that looks like it controls a post-action destination
(`redirect`, `next`, `url`, `return`, `callback`), try the payloads in `references/payloads.md`
and check whether the `Location` header ends up pointing at an attacker-controlled host.

**File upload** (if the site has any upload form — avatar, attachment, document) — see the
probes in `references/payloads.md`. The goal is proving the server accepts and serves back a
mismatched file type as-is; there's no need to prove actual code execution against a real
production box.

## Step 5: Business-logic / IDOR testing

For e-commerce or booking-style custom APIs (a hand-rolled PHP/Node endpoint, not a generic
CMS), the highest-value question is usually: **does the client control price/amount, or does the
server compute it?**

Approach: send a minimal/empty payload first to read the validation error, then add one field at
a time based on each new error message — this maps the required schema without guessing blindly.
Once you have a valid-shaped request, include a deliberately wrong price (e.g. `0`) alongside it
and see if the request succeeds. If the response doesn't echo the price back, that's inconclusive
by itself (see the read-access caveat above) — ask the user to check the actual stored value in
their DB/admin panel before calling it confirmed. If the table/collection has no price column at
all, the attack is architecturally impossible regardless of what the API accepts — check for that
before assuming the worst.

Also grep the site's JS bundles for leftover references to third-party backends (old Supabase
project URLs, API keys, etc.) that may be dead weight from a migration:

```bash
curl -s "https://target/" -o /tmp/home.html
grep -oE 'src="[^"]*\.js[^"]*"' /tmp/home.html
# download referenced bundles, then:
grep -oE '(https://[a-z0-9]+\.supabase\.co)' bundle.js
```

Verify with DNS whether a referenced host still resolves (`curl -s
"https://dns.google/resolve?name=HOST&type=A"`, look for `"Status":3` = NXDOMAIN) before flagging
it — a live browser session with network-request logging will also show you whether the frontend
actually calls that dead host or has since moved to something else (e.g. a same-origin PHP proxy),
which is the more useful thing to check than the dead reference itself.

## Step 6: Report

Group findings by severity, each backed by the actual request/response that demonstrates it —
never state a finding as fact without the evidence line:

- 🔴 **Critical** — exploitable now, real impact (auth bypass, data leak, free-money business logic)
- 🟠 **Significant** — real weakness, lower impact or needs a specific precondition (missing
  rate-limit, disclosed version numbers, missing CSP)
- 🟡 **Minor** — bad practice, not directly exploitable (no proper 404 page, verbose error pages)
- ✅ **Verified safe** — actively tested and held up (list these too — "didn't find anything" is
  weaker than "tried X, Y, Z and they were all handled correctly")

## Step 7: Remediation handoff

Offer to draft a copy-pasteable prompt for a Claude Code session running in the user's actual
project directory. Make it self-contained: include the exact request that demonstrated each
issue, the specific file/config pattern to look for, and concrete snippets where the fix is
well-known (nginx `add_header` blocks for security headers, Payload's `auth.maxLoginAttempts` /
`lockTime`, a server-side price-recalculation function). End the prompt by asking Claude Code to
report back the diff and the live re-check output (`curl -I`, a repeat of the failing test) so
there's something concrete to re-verify.

## Step 8: Re-verification after a fix is reported

Don't take a "fixed" report at face value — re-run the same checks independently, with
cache-busting query params (`?_cb=$(date +%s)`) so you're not looking at a cached response:

```bash
curl -sI "https://target/?_cb=$(date +%s)"
```

It's common for a fix to be committed and even reported as done while the actual deploy hasn't
happened yet (code changed locally, `dist` not yet uploaded to the host) — if headers/behavior
look unchanged, say so plainly and ask whether the deploy actually went out, rather than assuming
the report was wrong. Present the result as a clear before/after table per item.

## Throughout

- Never take destructive or hard-to-reverse actions: no real payments, no completing an actual
  checkout, no deleting real data, no locking out a real user's account, no actually exfiltrating
  data beyond what's needed to prove a misconfiguration exists (e.g. confirm a table is readable
  by fetching one record, don't dump the whole thing).
- Prefer the smallest test that answers the question. If a nonexistent-record 403 already tells
  you read access is restricted, you don't need to also brute-force IDs to look for real records.
- The user in this workflow communicates in Russian — write findings and the remediation prompt
  in Russian by default, unless they've been writing in English.
