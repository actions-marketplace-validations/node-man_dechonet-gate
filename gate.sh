#!/usr/bin/env bash
# DechoNet deploy gate — calls /api/util/gate and fails the step on pass=false.
set -euo pipefail
https=1; [ "${DN_HTTPS:-true}" = "false" ] && https=0
args=(--silent --show-error --max-time 90 --get "${DN_ENDPOINT:-https://dechonet.com}/api/util/gate"
  --data-urlencode "url=${DN_URL}" --data-urlencode "min_ssl=${DN_MIN_SSL:-B}" --data-urlencode "min_headers=${DN_MIN_HEADERS:-C}"
  --data-urlencode "min_days=${DN_MIN_DAYS:-14}" --data-urlencode "require_https=${https}" -H "User-Agent: DechoNet-Gate-Action/1.0")
[ -n "${DN_KEY:-}" ] && args+=(-H "Authorization: Bearer ${DN_KEY}")
body=$(curl "${args[@]}") || { echo "::error::DechoNet gate request failed"; exit 1; }
ok=$(jq -r '.ok' <<<"$body")
if [ "$ok" != "true" ]; then echo "::error::DechoNet: $(jq -r '.error.message // "error"' <<<"$body")"; exit 1; fi
pass=$(jq -r '.data.pass' <<<"$body")
unknown=$(jq '[.data.checks[] | select(.status == "unknown")] | length' <<<"$body")
{
  echo "### DechoNet deploy gate — $(jq -r '.data.host' <<<"$body")"
  echo
  echo "| Check | Result | Actual | Expected |"
  echo "|---|---|---|---|"
  jq -r '.data.checks[] | "| \(.key) | \(.status) | \(.actual) | \(.expected) |"' <<<"$body"
  echo
  echo "Full report: $(jq -r '.data.report' <<<"$body")"
} >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"
jq -r '.data.checks[] | select(.status == "fail") | "::error::\(.key): \(.actual) (expected \(.expected))"' <<<"$body"
jq -r '.data.checks[] | select(.status == "unknown") | "::warning::\(.key): could not be verified"' <<<"$body"
echo "pass=${pass}" >> "${GITHUB_OUTPUT:-/dev/null}"
if [ "$pass" != "true" ]; then exit 1; fi
if [ "${DN_UNKNOWN:-false}" = "true" ] && [ "$unknown" != "0" ]; then echo "::error::$unknown check(s) could not be verified"; exit 1; fi
echo "DechoNet gate passed."
