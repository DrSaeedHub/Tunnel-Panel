#!/usr/bin/env bash
#
# Validate an offline bundle the way an operator's server will read it.
#
#   scripts/offline/validate_bundle.sh <bundle.tar.gz> [--install-test]
#
# The default checks are safe anywhere: extraction, the SHA-256 manifest,
# structure, manifest-vs-filename agreement, script syntax, the APT index,
# and a network audit of the offline code path. With --install-test — meant
# for a disposable container of the bundle's own Ubuntu release, as root —
# it also actually installs the bundle's packages through the confined APT
# configuration and runs the offline installer far enough to prove the
# offline phases work, expecting it to stop at the documented "no systemd"
# exit code that a container honestly deserves.
#
# Every apt operation here runs with its HTTP and HTTPS access pointed at a
# dead proxy. A check that would pass with or without the network proves
# nothing about offline behaviour; this one fails loudly if anything tries
# to fetch.
set -Eeuo pipefail

pass() { printf 'ok: %s\n' "$*" >&2; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
trap 'printf "FAIL: validate_bundle.sh at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

TARBALL=""
INSTALL_TEST=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-test) INSTALL_TEST=1; shift ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 0 ;;
    *) TARBALL="$1"; shift ;;
  esac
done
[[ -n "$TARBALL" && -f "$TARBALL" ]] || fail "usage: validate_bundle.sh <bundle.tar.gz> [--install-test]; '$TARBALL' is not a file."

# ------------------------------------------------------------- the tarball

if [[ -f "$TARBALL.sha256" ]]; then
  (cd "$(dirname "$TARBALL")" && sha256sum --check --quiet "$(basename "$TARBALL").sha256")
  pass "tarball matches its .sha256 sidecar"
else
  fail "$TARBALL.sha256 is missing; every published bundle carries one."
fi

BUNDLE_NAME="$(basename "$TARBALL" .tar.gz)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

tar -xzf "$TARBALL" -C "$WORKDIR"
[[ -d "$WORKDIR/$BUNDLE_NAME" ]] || fail "the tarball does not extract to a directory named $BUNDLE_NAME."
ROOT="$WORKDIR/$BUNDLE_NAME"
pass "extracts to $BUNDLE_NAME/"

# ------------------------------------------------------------- the payload

(cd "$ROOT" && sha256sum --check --quiet checksums.sha256)
pass "checksums.sha256 verifies every payload file"

for required in manifest.json README_OFFLINE.md checksums.sha256 \
  scripts/install_offline.sh scripts/install.sh \
  apt-repo/Packages apt-repo/Packages.gz apt-repo/Release; do
  [[ -f "$ROOT/$required" ]] || fail "$required is missing from the bundle."
done
pass "required files are present"

manifest_field() {
  sed -n 's/.*"'"$1"'":[[:space:]]*"\([^"]*\)".*/\1/p' "$ROOT/manifest.json" | head -n1
}
M_VERSION="$(manifest_field version)"
M_UBUNTU="$(manifest_field ubuntu_version)"
M_ARCH="$(manifest_field architecture)"
M_TYPE="$(manifest_field bundle_type)"
[[ -n "$M_VERSION" && -n "$M_UBUNTU" && -n "$M_ARCH" && -n "$M_TYPE" ]] ||
  fail "manifest.json does not carry version, ubuntu_version, architecture and bundle_type."
EXPECTED_NAME="tunnel-panel-$M_VERSION-ubuntu$M_UBUNTU-$M_ARCH-$M_TYPE"
[[ "$BUNDLE_NAME" == "$EXPECTED_NAME" ]] ||
  fail "the manifest describes $EXPECTED_NAME but the file is named $BUNDLE_NAME; one of them is lying."
pass "manifest agrees with the bundle name ($EXPECTED_NAME)"

BINARY="$ROOT/dist/release/$M_VERSION/gre-panel-linux-$M_ARCH"
CLI="$ROOT/dist/release/$M_VERSION/tnp-linux-$M_ARCH"
[[ -f "$BINARY" && -f "$BINARY.sha256" && -f "$CLI" && -f "$CLI.sha256" ]] ||
  fail "the release artefacts or their per-file checksums are missing."
pass "release artefacts and per-file checksums are present"

bash -n "$ROOT/scripts/install_offline.sh"
bash -n "$ROOT/scripts/install.sh"
pass "both installer scripts parse"

# The binaries only run on their own architecture; elsewhere that is a fact
# about this host, reported rather than skipped silently.
HOST_ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
[[ "$HOST_ARCH" == "x86_64" ]] && HOST_ARCH=amd64
if [[ "$HOST_ARCH" == "$M_ARCH" ]]; then
  cp "$BINARY" "$WORKDIR/gre-panel.test" && chmod 0755 "$WORKDIR/gre-panel.test"
  "$WORKDIR/gre-panel.test" --version >/dev/null
  pass "the panel binary executes on this host and reports a version"
else
  printf 'skip: binary execution (host is %s, bundle is %s)\n' "$HOST_ARCH" "$M_ARCH" >&2
fi

# ------------------------------------------------------------ network audit
#
# The offline code path must not contain a single reachable fetch. The
# wrapper never runs a downloader at all, and it pins the delegated
# installer to the bundle's own release directory.

WRAPPER="$ROOT/scripts/install_offline.sh"
# Comment lines are prose and `command -v` is a presence test, not an
# invocation; both are excluded so the audit reads only what would run.
stripped="$(grep -v -e '^\s*#' -e 'command -v' "$WRAPPER")"
if printf '%s' "$stripped" | grep -nE '(curl|wget)\s' >&2; then
  fail "install_offline.sh invokes a downloader; the offline path must not."
fi
if printf '%s' "$stripped" | grep -nE 'https?://' >&2; then
  fail "install_offline.sh contains a URL; the offline path must not."
fi
for fragment in 'git clone' 'docker pull' 'snap install' 'add-apt-repository' 'pip install' 'npm install'; do
  if printf '%s' "$stripped" | grep -nF "$fragment" >&2; then
    fail "install_offline.sh contains '$fragment'."
  fi
done
grep -q -- '--release-base "\$RELEASE_BASE"' "$WRAPPER" ||
  fail "install_offline.sh no longer pins install.sh to the bundle's release directory."
grep -q 'RELEASE_BASE="\$BUNDLE_ROOT/dist/release"' "$WRAPPER" ||
  fail "RELEASE_BASE is not the bundle's own directory."
pass "network audit: the wrapper fetches nothing and pins install.sh to the bundle"

# ---------------------------------------------------------- the APT index

REPO="$ROOT/apt-repo"
while IFS= read -r file; do
  [[ -f "$REPO/${file#./}" ]] || fail "apt-repo/Packages names $file, which is not in the repository."
done < <(sed -n 's/^Filename: //p' "$REPO/Packages")
pass "every Filename in the Packages index exists"

for core in curl iproute2 openssl ca-certificates; do
  grep -q "^Package: $core$" "$REPO/Packages" || fail "the repository does not carry $core."
done
pass "the core packages are all indexed"

rel_sha="$(sed -n 's/^ \([0-9a-f]\{64\}\) *[0-9]* Packages$/\1/p' "$REPO/Release" | head -n1)"
act_sha="$(sha256sum "$REPO/Packages" | awk '{print $1}')"
[[ "$rel_sha" == "$act_sha" ]] || fail "the Release file's checksum does not match the Packages index."
pass "Release agrees with the Packages index"

# ------------------------------------ confined apt, with the network poisoned
#
# apt is given only the bundle repository and a proxy that cannot answer, in
# a private state directory. If resolution or download were to need the
# network, this fails — which is the point.

APT_T="$WORKDIR/apt"
mkdir -p "$APT_T/parts" "$APT_T/lists" "$APT_T/cache/archives/partial" "$APT_T/state"
printf 'deb [trusted=yes] file:%s ./\n' "$REPO" > "$APT_T/offline.list"

confined_apt() {
  DEBIAN_FRONTEND=noninteractive apt-get \
    -o Dir::Etc::sourcelist="$APT_T/offline.list" \
    -o Dir::Etc::sourceparts="$APT_T/parts" \
    -o Dir::State::lists="$APT_T/lists" \
    -o Acquire::http::Proxy="http://127.0.0.1:9" \
    -o Acquire::https::Proxy="http://127.0.0.1:9" \
    -o Acquire::Retries=0 \
    "$@"
}
rootless_apt() {
  confined_apt \
    -o Dir::Cache="$APT_T/cache" \
    -o Dir::State="$APT_T/state" \
    -o Dir::State::lists="$APT_T/lists" \
    -o Dir::State::status=/var/lib/dpkg/status \
    "$@"
}

if [[ "$(. /etc/os-release && printf '%s' "$VERSION_ID")" == "$M_UBUNTU" ]]; then
  rootless_apt update >/dev/null 2>&1 || fail "apt cannot read the bundled repository."
  pass "apt reads the bundled repository with the network poisoned"

  if [[ "$M_TYPE" == "bootstrap" ]]; then
    # The bootstrap promise: resolution succeeds from the bundle alone, even
    # on a host where nothing beyond the base system is installed.
    rootless_apt -s install --no-install-recommends curl iproute2 openssl ca-certificates >/dev/null 2>&1 ||
      fail "the bootstrap repository cannot satisfy the core packages on this host; the dependency closure is incomplete."
    pass "bootstrap closure satisfies the core packages on this host"
  fi

  if [[ $INSTALL_TEST -eq 1 ]]; then
    [[ $EUID -eq 0 ]] || fail "--install-test needs root."
    if [[ "$M_TYPE" == "bootstrap" ]]; then
      confined_apt update >/dev/null
      confined_apt install -y --no-install-recommends curl iproute2 openssl ca-certificates >/dev/null ||
        fail "installing the core packages from the bundle repository failed."
      if ! command -v curl >/dev/null || ! command -v ip >/dev/null; then
        fail "the packages installed but the commands are not on PATH."
      fi
      pass "core packages actually install from the bundle, network poisoned"
    fi

    # The installer itself, up to the honest limit of a container: it must
    # verify the bundle, check compatibility, ensure packages, delegate —
    # and then stop with exit 12, because a container has no systemd and
    # pretending otherwise would be a harness reporting a state the product
    # is not in.
    rc=0
    http_proxy="http://127.0.0.1:9" https_proxy="http://127.0.0.1:9" \
      "$ROOT/scripts/install_offline.sh" --non-interactive --json \
      --username validator --password 'validator-password' \
      --port 18443 --web-path validation >/dev/null 2>"$WORKDIR/installer.err" || rc=$?
    if [[ "$rc" -ne 12 ]]; then
      cat "$WORKDIR/installer.err" >&2
      fail "expected the installer to stop at exit 12 (no systemd in a container); it exited $rc."
    fi
    pass "install_offline.sh runs offline through every pre-systemd phase (stops at documented exit 12)"
  fi
else
  printf 'skip: apt resolution (host is not Ubuntu %s)\n' "$M_UBUNTU" >&2
fi

printf 'PASS: %s\n' "$BUNDLE_NAME" >&2
