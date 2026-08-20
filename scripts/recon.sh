#!/usr/bin/env bash
# Automated recon pass for site-security-audit: headers, SSL, redirect, fallback-page
# fingerprint, common exposed paths, CORS reflection, and cookie flags.
#
# Usage: recon.sh https://example.com
#
# This covers Steps 1-2 (and the new CORS/cookie checks) of SKILL.md mechanically so you
# don't have to hand-type the same curl loop every time. Read the output, don't just glance
# at exit codes — several checks here are judgment calls, not pass/fail.

set -u
CURL=$(command -v curl)
OPENSSL=$(command -v openssl)

if [ -z "${1:-}" ]; then
  echo "Usage: $0 https://target-site.com" >&2
  exit 1
fi

BASE="${1%/}"
HOST=$(echo "$BASE" | sed -E 's#^https?://##; s#/.*##')

echo "=================================================="
echo " RECON: $BASE"
echo "=================================================="

echo
echo "--- Headers ---"
$CURL -sI -L --max-time 15 "$BASE/"

echo
echo "--- Security headers present? ---"
HEADERS=$($CURL -sI -L --max-time 15 "$BASE/")
for h in "strict-transport-security" "content-security-policy" "x-frame-options" "x-content-type-options" "permissions-policy" "referrer-policy"; do
  if echo "$HEADERS" | grep -qi "^$h:"; then
    echo "  [OK]      $h"
  else
    echo "  [MISSING] $h"
  fi
done

echo
echo "--- SSL certificate ---"
if [ -n "$OPENSSL" ]; then
  echo | $OPENSSL s_client -connect "$HOST:443" -servername "$HOST" 2>/dev/null | $OPENSSL x509 -noout -dates -subject -issuer 2>/dev/null
fi

echo
echo "--- HTTP -> HTTPS redirect ---"
$CURL -sI --max-time 10 "http://$HOST/" | head -5

echo
echo "--- Fallback/catch-all page fingerprint ---"
RANDPATH="/nonexistent-random-$RANDOM$RANDOM"
FALLBACK_CODE=$($CURL -s -o /dev/null -w "%{http_code}" --max-time 8 "$BASE$RANDPATH")
FALLBACK_SIZE=$($CURL -s -o /dev/null -w "%{size_download}" --max-time 8 "$BASE$RANDPATH")
echo "  $RANDPATH -> HTTP $FALLBACK_CODE, ${FALLBACK_SIZE} bytes"
if [ "$FALLBACK_CODE" = "200" ]; then
  echo "  WARNING: nonexistent path returned 200 — this site has no real 404."
  echo "  Any '200' below for a 'sensitive' path is meaningless unless its size differs from ${FALLBACK_SIZE} bytes."
fi

echo
echo "--- Common exposed paths (compare size to fallback above, not just status code) ---"
for path in "/.env" "/.env.local" "/.git/config" "/.git/HEAD" "/wp-config.php.bak" "/backup.zip" "/backup.sql" "/config.php" "/.htaccess" "/admin" "/wp-admin/" "/wp-login.php" "/phpmyadmin" "/xmlrpc.php" "/CHANGELOG.md" "/readme.html" "/server-status" "/.well-known/security.txt" "/robots.txt" "/sitemap.xml"; do
  CODE=$($CURL -s -o /dev/null -w "%{http_code}" --max-time 8 "$BASE$path")
  SIZE=$($CURL -s -o /dev/null -w "%{size_download}" --max-time 8 "$BASE$path")
  FLAG=""
  if [ "$CODE" = "200" ] && [ "$SIZE" = "$FALLBACK_SIZE" ]; then
    FLAG="  (== fallback page, likely not real)"
  fi
  echo "  $path -> HTTP $CODE, ${SIZE} bytes$FLAG"
done

echo
echo "--- CORS reflection check ---"
EVIL_ORIGIN="https://evil-cors-test-$RANDOM.example"
CORS_HEADER=$($CURL -s -D - -o /dev/null --max-time 10 -H "Origin: $EVIL_ORIGIN" "$BASE/" | grep -i "access-control-allow-origin")
if echo "$CORS_HEADER" | grep -qi "$EVIL_ORIGIN"; then
  echo "  WARNING: arbitrary Origin reflected back: $CORS_HEADER"
  echo "  If Access-Control-Allow-Credentials: true is also set, this is a real cross-origin data-theft vector."
elif echo "$CORS_HEADER" | grep -q '\*'; then
  echo "  Access-Control-Allow-Origin: * (wildcard — fine for public GET APIs, bad if credentials/cookies are involved)"
elif [ -n "$CORS_HEADER" ]; then
  echo "  $CORS_HEADER (not reflecting arbitrary origins — good)"
else
  echo "  No Access-Control-Allow-Origin header on this path (may still exist on specific API routes — test those directly too)."
fi

echo
echo "--- Cookie flags ---"
COOKIES=$($CURL -sI -L --max-time 10 "$BASE/" | grep -i "^set-cookie:")
if [ -z "$COOKIES" ]; then
  echo "  No cookies set on homepage (check login/session endpoints separately)."
else
  echo "$COOKIES" | while IFS= read -r line; do
    NAME=$(echo "$line" | sed -E 's/^[Ss]et-[Cc]ookie: ([^=]+)=.*/\1/')
    MISSING=""
    echo "$line" | grep -qi "secure" || MISSING="$MISSING Secure"
    echo "$line" | grep -qi "httponly" || MISSING="$MISSING HttpOnly"
    echo "$line" | grep -qi "samesite" || MISSING="$MISSING SameSite"
    if [ -n "$MISSING" ]; then
      echo "  $NAME -> missing:$MISSING"
    else
      echo "  $NAME -> OK (Secure, HttpOnly, SameSite all present)"
    fi
  done
fi

echo
echo "=================================================="
echo " Done. This is mechanical recon only — see SKILL.md"
echo " Steps 4-6 for form/auth/business-logic testing,"
echo " which needs actual judgment and can't be scripted."
echo "=================================================="
