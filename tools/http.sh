#!/usr/bin/env bash
# http.sh — thin curl wrapper that captures RAW request + response as evidence.
#
# Usage:
#   tools/http.sh <out_prefix> <curl-args...>
#
# Writes:
#   <out_prefix>.request.http   (method/url/headers/body you sent)
#   <out_prefix>.response.http  (status line + headers + body received)
#   <out_prefix>.meta.json      (timing + http_code, for blind/time-based checks)
#
# Example (IDOR baseline):
#   tools/http.sh findings/evidence/F-001/request-a \
#     -X GET "https://LAB.web-security-academy.net/api/user/1" \
#     -H "Cookie: session=abc"
#
# Keep evidence raw and reproducible. Do NOT edit captured files by hand.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <out_prefix> <curl-args...>" >&2
  exit 2
fi

prefix="$1"; shift
mkdir -p "$(dirname "$prefix")"

# Record the invocation (what was sent) for reproducibility.
{
  echo "# curl invocation (captured $(date -u +%FT%TZ))"
  printf 'curl'; for a in "$@"; do printf ' %q' "$a"; done; printf '\n'
} > "${prefix}.request.http"

# Perform the request; capture headers+body and timing/status via -w.
http_code=$(curl -sS -D "${prefix}.response.headers" \
  -o "${prefix}.response.body" \
  -w '%{http_code} %{time_total}' "$@") || true

code="${http_code%% *}"
time_total="${http_code##* }"

# Assemble a single raw response file (headers then body).
cat "${prefix}.response.headers" > "${prefix}.response.http" 2>/dev/null || true
echo >> "${prefix}.response.http"
cat "${prefix}.response.body" >> "${prefix}.response.http" 2>/dev/null || true
rm -f "${prefix}.response.headers" "${prefix}.response.body"

cat > "${prefix}.meta.json" <<JSON
{ "http_code": "${code}", "time_total_seconds": "${time_total}", "captured_at": "$(date -u +%FT%TZ)" }
JSON

echo "saved: ${prefix}.request.http ${prefix}.response.http ${prefix}.meta.json"
echo "http_code=${code} time_total=${time_total}s"
