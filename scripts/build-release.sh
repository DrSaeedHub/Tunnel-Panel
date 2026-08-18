#!/usr/bin/env bash
#
# Build release artefacts.
#
# Produces a static binary per architecture with the version, commit and build
# date stamped in, plus the SHA256SUMS file the installer verifies against.
# The frontend is built first, so the bundle embedded in the binary is always
# the one in the working tree rather than whatever was there last time.
#
#   scripts/build-release.sh [--version v0.1.0] [--output dist/release]
#                            [--arch amd64,arm64] [--skip-frontend]
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VERSION=""
OUTPUT="dist/release"
ARCHES="amd64,arm64"
SKIP_FRONTEND=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --output) OUTPUT="${2:?--output needs a value}"; shift 2 ;;
    --arch) ARCHES="${2:?--arch needs a value}"; shift 2 ;;
    --skip-frontend) SKIP_FRONTEND=1; shift ;;
    -h|--help)
      sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

step() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }

# A Go release extracted to /usr/local/go is not on a login shell's PATH on
# every machine, and a release build failing with "go: command not found" three
# lines in is a waste of everyone's time.
[[ -x /usr/local/go/bin/go ]] && PATH="/usr/local/go/bin:$PATH"
command -v go >/dev/null 2>&1 || { echo "go is not on PATH" >&2; exit 3; }

# The version defaults to the current tag, falling back to a commit-derived
# label so an untagged build is still identifiable rather than "dev".
if [[ -z "$VERSION" ]]; then
  VERSION="$(git describe --tags --exact-match 2>/dev/null || true)"
  [[ -n "$VERSION" ]] || VERSION="0.0.0-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
fi

# The stamp comes from git, or from the environment when there is no checkout
# to ask. That is not a corner case: the documented way to deploy is to build
# the release and carry it to the target, and a tree exported with `git archive`
# — which is also how a build gets onto a host whose only copy of the source
# arrived over scp — has no .git at all. Without these, such a build stamps
# itself "unknown" and the panel can no longer say which commit it is running,
# which is the one thing the version banner exists for.
COMMIT="${GRE_PANEL_BUILD_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
# Reproducible where the tree is: the commit's own date rather than "now", so
# rebuilding the same commit twice produces the same binary.
BUILD_DATE="${GRE_PANEL_BUILD_DATE:-$(git show -s --format=%cI HEAD 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)}"

step "Version $VERSION (commit $COMMIT, $BUILD_DATE)"

if [[ $SKIP_FRONTEND -eq 0 ]]; then
  step "Building the frontend"
  if ! command -v npm >/dev/null 2>&1; then
    echo "npm is required to build the frontend; pass --skip-frontend to use the committed bundle" >&2
    exit 3
  fi
  (
    cd web/_app
    # `npm ci` when there is a lockfile and no install yet, so a clean machine
    # produces exactly the tested dependency tree.
    if [[ ! -d node_modules ]]; then npm ci; fi
    npm run build
  )
fi

[[ -f web/dist/index.html ]] || { echo "web/dist/index.html is missing; the frontend was never built" >&2; exit 3; }

mkdir -p "$OUTPUT"
rm -f "$OUTPUT"/gre-panel-linux-* "$OUTPUT"/tnp-linux-* "$OUTPUT/SHA256SUMS"

LDFLAGS="-s -w"
LDFLAGS="$LDFLAGS -X main.version=$VERSION"
LDFLAGS="$LDFLAGS -X main.commit=$COMMIT"
LDFLAGS="$LDFLAGS -X main.buildDate=$BUILD_DATE"

IFS=',' read -r -a ARCH_LIST <<< "$ARCHES"
for arch in "${ARCH_LIST[@]}"; do
  # The panel and its management CLI, stamped identically. tnp reports the same
  # version and commit as the panel it manages, so `tnp status` showing two
  # different builds is a real fact about the host rather than a build artefact.
  for component in gre-panel tnp; do
    target="$OUTPUT/$component-linux-$arch"
    step "Building $target"
    # CGO off is what makes the binary static: the SQLite driver is pure Go, so
    # nothing links against libc and the binary runs on any glibc or musl host.
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
      go build -trimpath -ldflags "$LDFLAGS" -o "$target" "./cmd/$component"

    # Prove it rather than assume it — and say so plainly when this host cannot.
    bash "$REPO_ROOT/scripts/check-static.sh" "$target"
    printf '    size: %s bytes\n' "$(stat -c%s "$target")" >&2
  done
done

step "Writing $OUTPUT/SHA256SUMS"
(
  cd "$OUTPUT"
  # Bare filenames, so the installer can verify from any directory.
  sha256sum gre-panel-linux-* tnp-linux-* > SHA256SUMS
  # A per-file sum as well: the installer downloads one binary and its own
  # checksum rather than the whole manifest.
  for file in gre-panel-linux-* tnp-linux-*; do
    [[ "$file" == *.sha256 ]] && continue
    sha256sum "$file" > "$file.sha256"
  done
  cat SHA256SUMS >&2
)

step "Done. Artefacts in $OUTPUT"
