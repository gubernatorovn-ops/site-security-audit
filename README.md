# site-security-audit

A [Claude Code](https://claude.com/claude-code) skill that runs a hands-on security audit of a
live website you own or are authorized to test: response headers, exposed config/backup files, an
automated [nuclei](https://github.com/projectdiscovery/nuclei) scan, live probing of
login/registration forms for SQLi/NoSQLi/XSS and brute-force protection, and business-logic checks
(mass assignment, price manipulation, IDOR) on custom APIs.

It always confirms authorization before any active testing, and refuses to scan a site you don't
own or aren't authorized to test.

## Install

```bash
git clone https://github.com/<your-username>/site-security-audit ~/.claude/skills/site-security-audit
```

Or just download `SKILL.md` and drop it into `~/.claude/skills/site-security-audit/SKILL.md`.

Claude Code picks up any skill under `~/.claude/skills/` automatically — no build step, no
dependencies to install ahead of time (the skill will ask before installing `nuclei` via Homebrew
if you want the automated scan step).

## Use

Just ask, e.g.:

> проверь мой сайт example.com на уязвимости

> can you run a security check on my site before I ship this?

The skill walks through recon, exposed-path checks, an optional nuclei scan, form/auth testing,
and business-logic checks, then reports findings by severity with the evidence behind each one —
and can draft a copy-pasteable fix-it prompt for a Claude Code session in your project.

## License

MIT
