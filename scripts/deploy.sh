#!/usr/bin/env bash
#
# Build, publish, and only then install.
#
# The order is the point. Deploying used to mean building locally and
# installing straight onto each host, which works and leaves the published
# release untouched — so the published release drifted behind the hosts, and
# anyone reinstalling from the documented one-liner silently got an older
# build. Nobody forgot a step; there was no step. So publishing is part of
# deploying here, and the artefact an operator would download is the same
# object that reaches the hosts — by construction rather than by discipline.
#
#   scripts/deploy.sh --version v0.1.1 [--host srva --host srvb]
#                     [--publish-only] [--skip-frontend] [--skip-tests]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VERSION=""
HOSTS=()
PUBLISH_ONLY=0
SKIP_FRONTEND=0
SKIP_TESTS=0
RELEASE_ROOT="dist/release"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --host) HOSTS+=("${2:?--host needs a value}"); shift 2 ;;
    --publish-only) PUBLISH_ONLY=1; shift ;;
    --skip-frontend) SKIP_FRONTEND=1; shift ;;
    --skip-tests) SKIP_TESTS=1; shift ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

step() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ -n "$VERSION" ]] || fail "--version is required; a release without a name cannot be pinned to."

# A dirty tree publishes something no commit describes, and the commit stamped
# into the binary would then be a lie about what is in it.
if [[ -n "$(git status --porcelain)" ]]; then
  fail "the working tree has uncommitted changes; the commit stamped into the binary would not describe it"
fi
COMMIT="$(git rev-parse --short HEAD)"

if [[ $SKIP_TESTS -eq 0 ]]; then
  step "Running the Go suite"
  bash "$REPO_ROOT/scripts/test-go.sh" >/dev/null || fail "the Go suite is not green; nothing was published"
fi

# ---------------------------------------------------------------- build

BUILD_ARGS=(--version "$VERSION" --output "$RELEASE_ROOT/$VERSION")
[[ $SKIP_FRONTEND -eq 1 ]] && BUILD_ARGS+=(--skip-frontend)

step "Building $VERSION ($COMMIT)"
bash "$REPO_ROOT/scripts/build-release.sh" "${BUILD_ARGS[@]}"

# ---------------------------------------------------------------- publish

# The checksums have to describe the files actually sitting there before any of
# them is uploaded. A SHA256SUMS copied from a previous build is exactly the
# kind of thing nobody notices until an installer refuses.
( cd "$RELEASE_ROOT/$VERSION" && sha256sum -c SHA256SUMS >/dev/null ) ||
  fail "the checksums in $RELEASE_ROOT/$VERSION/SHA256SUMS do not match the files there"
step "checksums verify against the built artefacts"

command -v gh >/dev/null 2>&1 ||
  fail "the GitHub CLI (gh) is required to publish a release; install it and run 'gh auth login'"

# The release is created if the tag has never been published, and its assets
# replaced if it has — a re-run of the same version overwrites rather than
# failing halfway with some assets old and some new. Marking it latest is what
# makes the one-liner's default resolve to this build: GitHub's "latest" is a
# pointer to a release, not a directory somebody can forget to update.
step "Publishing $VERSION to GitHub Releases"
if gh release view "$VERSION" >/dev/null 2>&1; then
  gh release upload "$VERSION" "$RELEASE_ROOT/$VERSION"/* --clobber ||
    fail "uploading the assets for $VERSION failed"
  gh release edit "$VERSION" --latest >/dev/null ||
    fail "marking $VERSION as the latest release failed"
else
  gh release create "$VERSION" "$RELEASE_ROOT/$VERSION"/* \
    --title "$VERSION" --generate-notes --latest ||
    fail "creating the release $VERSION failed"
fi

printf '\n  Published:\n' >&2
( cd "$RELEASE_ROOT/$VERSION" && sha256sum -- * 2>/dev/null | grep -v SHA256SUMS | sed 's/^/    /' ) >&2
printf '\n' >&2

if [[ $PUBLISH_ONLY -eq 1 || ${#HOSTS[@]} -eq 0 ]]; then
  step "Published. No hosts were given, so nothing was installed."
  exit 0
fi

# ---------------------------------------------------------------- install
#
# Through the published one-liner rather than by copying a binary over, so what
# is proven is the path an operator actually uses.

for host in "${HOSTS[@]}"; do
  step "Installing on $host through the published installer"
  ssh -o ConnectTimeout=20 "$host" \
    "bash <(curl -Ls https://raw.githubusercontent.com/DrSaeedHub/Tunnel-Panel/main/scripts/install.sh) --upgrade --yes --json" ||
    fail "installing on $host failed"
done

step "Checking that the hosts run what was published"
bash "$REPO_ROOT/scripts/check-deployed.sh" "${HOSTS[@]}"
