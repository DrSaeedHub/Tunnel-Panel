#!/usr/bin/env bash
#
# Put the tracked hooks into .git/hooks.
#
# git does not clone hooks, so a tracked copy is the only way one survives, and
# this is what installs it. Run it once after cloning:
#
#   scripts/install-hooks.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

target="$(git rev-parse --git-path hooks)"
mkdir -p "$target"

for hook in scripts/hooks/*; do
  name="$(basename "$hook")"
  install -m 0755 "$hook" "$target/$name"
  printf 'installed %s\n' "$target/$name" >&2
done
