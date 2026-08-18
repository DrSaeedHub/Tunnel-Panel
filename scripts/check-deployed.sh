#!/usr/bin/env bash
#
# Compare what the release host serves against what the servers actually run.
#
# This is the check that would have caught the drift nobody noticed: a
# published release left behind while one host ran a directly built binary and
# another ran the stale published one. Two facts existed and nothing compared
# them.
#
#   scripts/check-deployed.sh srva srvb
#   scripts/check-deployed.sh --base https://example/dist/release srva
#
# Exits non-zero when a host runs something other than what latest/ serves.
set -euo pipefail

RELEASE_BASE="https://github.com/DrSaeedHub/Tunnel-Panel/releases/download"
HOSTS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base) RELEASE_BASE="${2:?--base needs a value}"; shift 2 ;;
    -h|--help) sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) HOSTS+=("$1"); shift ;;
  esac
done
[[ ${#HOSTS[@]} -gt 0 ]] || { echo "name at least one host" >&2; exit 2; }

step() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }

# GitHub serves the moving pointer as .../releases/latest/download/<file>,
# while a directory-served base is <base>/latest/<file>. The installer resolves
# the same difference; this has to resolve it the same way, or it would compare
# the hosts against something no operator downloads.
if [[ "$RELEASE_BASE" == */releases/download ]]; then
  MANIFEST_URL="${RELEASE_BASE%/download}/latest/download/SHA256SUMS"
else
  MANIFEST_URL="$RELEASE_BASE/latest/SHA256SUMS"
fi

# The published checksum, taken from the release host rather than from the local
# dist/ directory: what matters is what an operator would download, and a local
# copy that was never uploaded would compare clean against itself.
step "Reading the published checksums from $MANIFEST_URL"
published="$(curl -fsSL "$MANIFEST_URL")" || {
  echo "could not read $MANIFEST_URL" >&2
  exit 1
}
printf '%s\n' "$published" | sed 's/^/    /' >&2

want_panel="$(printf '%s\n' "$published" | awk '$2 ~ /gre-panel-linux-amd64$/ || $2 ~ /^\*?gre-panel-linux-amd64$/ {print $1}' | head -n1)"
want_cli="$(printf '%s\n' "$published" | awk '$2 ~ /tnp-linux-amd64$/ {print $1}' | head -n1)"
[[ -n "$want_panel" ]] || { echo "the published manifest names no gre-panel-linux-amd64" >&2; exit 1; }

failures=0
for host in "${HOSTS[@]}"; do
  step "$host"
  # shellcheck disable=SC2029  # the remote command is deliberately expanded here
  read -r got_panel got_cli version commit < <(ssh -o ConnectTimeout=20 "$host" '
    panel=$(sha256sum /usr/local/bin/gre-panel 2>/dev/null | awk "{print \$1}")
    cli=$(sha256sum /usr/local/bin/tnp 2>/dev/null | awk "{print \$1}")
    v=$(/usr/local/bin/gre-panel --version 2>/dev/null | head -1 | awk "{print \$NF}")
    c=$(/usr/local/bin/gre-panel --version 2>/dev/null | sed -n "s/^commit:[[:space:]]*//p")
    printf "%s %s %s %s\n" "${panel:-none}" "${cli:-none}" "${v:-none}" "${c:-none}"
  ')

  printf '    running   %s %s\n' "${version}" "${commit}" >&2
  if [[ "$got_panel" == "$want_panel" ]]; then
    printf '    panel     matches what latest/ serves\n' >&2
  else
    printf '    panel     DIFFERS\n      published %s\n      running   %s\n' \
      "$want_panel" "$got_panel" >&2
    failures=$((failures + 1))
  fi

  if [[ -z "$want_cli" ]]; then
    printf '    cli       latest/ publishes no tnp binary\n' >&2
  elif [[ "$got_cli" == "$want_cli" ]]; then
    printf '    cli       matches what latest/ serves\n' >&2
  else
    printf '    cli       DIFFERS\n      published %s\n      running   %s\n' \
      "$want_cli" "$got_cli" >&2
    failures=$((failures + 1))
  fi
done

if (( failures > 0 )); then
  printf '\n  %d mismatch(es). A host is running something other than what the one-liner installs,\n' "$failures" >&2
  printf '  which means the documented install path does not produce what is on these machines.\n' >&2
  exit 1
fi
step "Every host runs exactly what the latest release serves."
