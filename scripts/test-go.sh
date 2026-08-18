#!/usr/bin/env bash
#
# Run the Go suite on Linux.
#
# The panel is a Linux program and several of its packages reason about Linux
# paths, Linux file modes and netlink. Run on a Windows checkout the suite is
# red for reasons that have nothing to do with the panel: filepath.Abs prefixes
# a drive letter, os.Stat synthesises 0666 from the read-only attribute, and the
# netlink health component correctly reports that netlink is not available —
# which turns every health assertion into a 503. Those are facts about the
# machine reading the code, not about the code.
#
# From a Windows workstation with WSL this is the one-liner that gives a
# meaningful answer:
#
#   wsl -d Ubuntu-24.04 -- bash /mnt/c/path/to/repo/scripts/test-go.sh
#
# On a Linux host it is just `scripts/test-go.sh`.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This suite is meaningful on Linux only; see the comment at the top of this script." >&2
  exit 2
fi

for candidate in /usr/local/go/bin go; do
  if [[ -x "$candidate/go" ]]; then PATH="$candidate:$PATH"; break; fi
done
command -v go >/dev/null 2>&1 || {
  echo "go is not on PATH. Install it, or extract a release to /usr/local/go." >&2
  exit 2
}

echo "==> $(go version)" >&2
# With no arguments, the whole tree. With arguments, exactly what was asked for,
# so a single package can be run without the other twenty answering "cached".
if [[ $# -eq 0 ]]; then
  exec go test ./...
fi
exec go test "$@"
