#!/usr/bin/env bash
#
# Build one offline installation bundle.
#
# A bundle is a tar.gz that installs the panel on a server with no internet
# access: the release binaries, the installer, and a local APT repository
# holding every OS package the installer or the panel could need on that
# Ubuntu release. The panel itself is a static binary with no libc
# dependency, so the OS packages are the only part of the bundle that is
# release-specific — which is why this script refuses to build a bundle for
# an Ubuntu release other than the one it is running on: the dependency
# closure is resolved against the running system's package universe, and a
# closure computed on 24.04 describes 24.04, whatever name it is given.
#
#   scripts/offline/build_bundle.sh --ubuntu 22.04 --flavor standard \
#       --version v1.9.0 [--release-dir dist/release/v1.9.0] \
#       [--arch amd64] [--output dist/offline] [--clean]
#
# Flavors:
#   standard    for a normal Ubuntu Server. Carries the packages the panel
#               and installer use directly (curl, iproute2, openssl,
#               ca-certificates); their dependencies are assumed present, as
#               they are on any healthy server installation.
#   bootstrap   for a minimal Ubuntu. Carries the full recursive dependency
#               closure of the same packages, so the local repository can
#               satisfy apt on a system where nothing beyond the base is
#               installed.
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

step() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

trap 'printf "\033[1;31merror:\033[0m build_bundle.sh failed at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

# ---------------------------------------------------------------- arguments

UBUNTU=""
FLAVOR=""
ARCH="amd64"
VERSION=""
RELEASE_DIR=""
OUTPUT="$REPO_ROOT/dist/offline"
CLEAN=0

usage() {
  sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ubuntu) UBUNTU="${2:?--ubuntu needs a value}"; shift 2 ;;
    --flavor) FLAVOR="${2:?--flavor needs a value}"; shift 2 ;;
    --arch) ARCH="${2:?--arch needs a value}"; shift 2 ;;
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --release-dir) RELEASE_DIR="${2:?--release-dir needs a value}"; shift 2 ;;
    --output) OUTPUT="${2:?--output needs a value}"; shift 2 ;;
    --clean) CLEAN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; fail "unknown argument: $1" ;;
  esac
done

case "$UBUNTU" in
  22.04|24.04) ;;
  *) fail "--ubuntu must be 22.04 or 24.04; only those releases are built and tested." ;;
esac
case "$FLAVOR" in
  standard|bootstrap) ;;
  *) fail "--flavor must be standard or bootstrap." ;;
esac
case "$ARCH" in
  amd64) ;;
  *) fail "--arch must be amd64; no other architecture's packages are resolved or tested." ;;
esac
[[ -n "$VERSION" ]] || fail "--version is required; a bundle without a version cannot be pinned to."
[[ -n "$RELEASE_DIR" ]] || RELEASE_DIR="$REPO_ROOT/dist/release/$VERSION"

# ------------------------------------------------------------ host suitability
#
# The dependency closure is resolved by this host's apt against this host's
# package universe. Building a 22.04 bundle on a 24.04 host would fill the
# repository with 24.04 packages under a 22.04 label — the exact lie the
# manifest exists to prevent.

HOST_ID="$(. /etc/os-release && printf '%s' "$ID")"
HOST_VERSION="$(. /etc/os-release && printf '%s' "$VERSION_ID")"
HOST_CODENAME="$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")"
[[ "$HOST_ID" == "ubuntu" ]] || fail "this script must run on Ubuntu; it is running on '$HOST_ID'."
[[ "$HOST_VERSION" == "$UBUNTU" ]] ||
  fail "building a $UBUNTU bundle requires running on Ubuntu $UBUNTU (this host is $HOST_VERSION); the package closure is resolved against the running system."

HOST_ARCH="$(dpkg --print-architecture)"
[[ "$HOST_ARCH" == "$ARCH" ]] ||
  fail "building an $ARCH bundle requires an $ARCH host (this host is $HOST_ARCH); apt downloads the running architecture's packages."

for tool in apt-get apt-cache dpkg-deb sha256sum gzip tar; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required and was not found."
done

# ----------------------------------------------------------- release artefacts

BINARY="gre-panel-linux-$ARCH"
CLI="tnp-linux-$ARCH"
for artefact in "$BINARY" "$CLI"; do
  [[ -f "$RELEASE_DIR/$artefact" ]] || fail "$RELEASE_DIR/$artefact is missing; build the release first (scripts/build-release.sh --version $VERSION)."
  [[ -f "$RELEASE_DIR/$artefact.sha256" ]] || fail "$RELEASE_DIR/$artefact.sha256 is missing; the installer verifies against it and cannot without it."
  expected="$(awk '{print $1}' "$RELEASE_DIR/$artefact.sha256" | head -n1)"
  actual="$(sha256sum "$RELEASE_DIR/$artefact" | awk '{print $1}')"
  [[ "$expected" == "$actual" ]] || fail "$artefact does not match its recorded checksum; the release directory is damaged."
done
step "Release artefacts in $RELEASE_DIR verify against their checksums"

# ---------------------------------------------------------------- workspace

BUNDLE_NAME="tunnel-panel-$VERSION-ubuntu$UBUNTU-$ARCH-$FLAVOR"
WORK="$OUTPUT/work/$BUNDLE_NAME"
STAGE="$WORK/stage/$BUNDLE_NAME"

if [[ $CLEAN -eq 1 ]]; then
  rm -rf "$WORK"
fi
rm -rf "$WORK/stage"
mkdir -p "$WORK/debs" "$STAGE/scripts" "$STAGE/apt-repo" "$STAGE/dist/release/$VERSION" "$OUTPUT"

# A large closure download needs room to land in.
available_kb="$(df --output=avail -k "$OUTPUT" | tail -n1 | tr -d ' ')"
needed_kb=300000
[[ "$FLAVOR" == "bootstrap" ]] && needed_kb=1500000
(( available_kb > needed_kb )) ||
  fail "only $((available_kb / 1024)) MB free under $OUTPUT; at least $((needed_kb / 1024)) MB is needed to build a $FLAVOR bundle."

# ------------------------------------------------------------- package closure
#
# What the installer and the panel actually use, determined from the code
# rather than guessed:
#   iproute2         the panel drives `ip`, and the installer checks ports
#                    with `ss`
#   curl             the installer's health poll and first-account POST are
#                    HTTP to localhost; curl or wget is required
#   openssl          proposes the random web path (a /dev/urandom fallback
#                    exists, but the documented default path uses openssl)
#   ca-certificates  curl's TLS roots, so the same curl works online later
PACKAGES=(ca-certificates curl iproute2 openssl)

# Standard-set proxies are honoured during this ONLINE build only; nothing in
# the produced bundle touches the network.
APT_PROXY_OPTS=()
[[ -n "${http_proxy:-${HTTP_PROXY:-}}" ]] && APT_PROXY_OPTS+=(-o "Acquire::http::Proxy=${http_proxy:-$HTTP_PROXY}")
[[ -n "${https_proxy:-${HTTPS_PROXY:-}}" ]] && APT_PROXY_OPTS+=(-o "Acquire::https::Proxy=${https_proxy:-$HTTPS_PROXY}")

resolve_package_list() {
  if [[ "$FLAVOR" == "standard" ]]; then
    printf '%s\n' "${PACKAGES[@]}"
    return 0
  fi
  # The full recursive closure, down to libc. Lines starting at column zero
  # are package names; virtual packages appear in <angle brackets> and are
  # excluded, because apt resolves them through a real provider that is
  # already in the list.
  apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts \
    --no-breaks --no-replaces --no-enhances "${PACKAGES[@]}" |
    grep -E '^[a-zA-Z0-9]' | sort -u
}

step "Resolving the $FLAVOR package list for Ubuntu $UBUNTU"
mapfile -t CANDIDATES < <(resolve_package_list)
(( ${#CANDIDATES[@]} >= ${#PACKAGES[@]} )) || fail "package resolution produced ${#CANDIDATES[@]} names, fewer than the ${#PACKAGES[@]} requested; apt-cache is not answering."

# A name the closure produces is not necessarily downloadable: pure-virtual
# packages have no candidate version. They are dropped here with a record of
# why, and anything real that then fails to download is a hard error below.
DOWNLOADABLE=()
for pkg in "${CANDIDATES[@]}"; do
  candidate="$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/{print $2}')"
  if [[ -z "$candidate" || "$candidate" == "(none)" ]]; then
    warn "skipping '$pkg': no installation candidate (virtual package)"
    continue
  fi
  DOWNLOADABLE+=("$pkg")
done
step "${#DOWNLOADABLE[@]} packages to download"

step "Downloading packages into the local repository"
(
  cd "$WORK/debs"
  # Downloaded one at a time so the failure message can name the package. A
  # bundle whose repository is missing one dependency is not a bundle; it is
  # a delayed installation failure on a machine with no way to recover.
  for pkg in "${DOWNLOADABLE[@]}"; do
    if ! apt-get download "${APT_PROXY_OPTS[@]}" "$pkg" >/dev/null 2>&1; then
      # One retry: a mirror mid-sync produces transient 404s.
      sleep 2
      apt-get download "${APT_PROXY_OPTS[@]}" "$pkg" >/dev/null ||
        fail "could not download '$pkg'; the bundle would be incomplete, so nothing was produced."
    fi
  done
)

DEB_COUNT="$(find "$WORK/debs" -maxdepth 1 -name '*.deb' | wc -l)"
(( DEB_COUNT >= ${#DOWNLOADABLE[@]} )) ||
  fail "downloaded $DEB_COUNT .deb files for ${#DOWNLOADABLE[@]} packages; something did not land."
step "$DEB_COUNT .deb files downloaded"

# --------------------------------------------------------- the APT repository
#
# A flat repository: debs, a Packages index, and a Release file naming its
# checksums. The bundle repository is immutable and covered by the bundle's
# own SHA-256 manifest, which the installer verifies before apt ever reads
# this index — that is what makes [trusted=yes] on the installer's side an
# accounted-for decision rather than a shrug.

cp -f "$WORK/debs"/*.deb "$STAGE/apt-repo/"

step "Generating the repository index"
(
  cd "$STAGE/apt-repo"
  if command -v dpkg-scanpackages >/dev/null 2>&1; then
    dpkg-scanpackages --multiversion . /dev/null 2>/dev/null | sed 's|^Filename: \./|Filename: ./|' > Packages
  else
    # dpkg-scanpackages lives in dpkg-dev, which a build host may not have.
    # The index it produces is control fields plus Filename/Size/hashes, all
    # of which dpkg-deb and coreutils can supply.
    : > Packages
    for deb in *.deb; do
      dpkg-deb -f "$deb" >> Packages
      printf 'Filename: ./%s\n' "$deb" >> Packages
      printf 'Size: %s\n' "$(stat -c%s "$deb")" >> Packages
      printf 'MD5sum: %s\n' "$(md5sum "$deb" | awk '{print $1}')" >> Packages
      printf 'SHA256: %s\n' "$(sha256sum "$deb" | awk '{print $1}')" >> Packages
      printf '\n' >> Packages
    done
  fi
  gzip -9 -n -c Packages > Packages.gz

  # A minimal Release file, handwritten rather than via apt-ftparchive so the
  # build does not depend on apt-utils. apt wants the index checksums.
  {
    printf 'Origin: tunnel-panel-offline\n'
    printf 'Label: tunnel-panel-offline\n'
    printf 'Suite: local\n'
    printf 'Codename: local\n'
    printf 'Architectures: %s\n' "$ARCH"
    printf 'Description: Offline package repository for the GRE tunnel panel bundle\n'
    printf 'SHA256:\n'
    printf ' %s %16s Packages\n' "$(sha256sum Packages | awk '{print $1}')" "$(stat -c%s Packages)"
    printf ' %s %16s Packages.gz\n' "$(sha256sum Packages.gz | awk '{print $1}')" "$(stat -c%s Packages.gz)"
  } > Release
)

grep -q '^Package: curl$' "$STAGE/apt-repo/Packages" || fail "the generated Packages index does not list curl; the index generator is not working."

# ------------------------------------------------------------ bundle payload

step "Assembling the bundle payload"
for artefact in "$BINARY" "$CLI"; do
  cp -f "$RELEASE_DIR/$artefact" "$RELEASE_DIR/$artefact.sha256" "$STAGE/dist/release/$VERSION/"
done
(
  cd "$STAGE/dist/release/$VERSION"
  sha256sum "$BINARY" "$CLI" > SHA256SUMS
)

cp -f "$REPO_ROOT/scripts/install.sh" "$STAGE/scripts/install.sh"
cp -f "$REPO_ROOT/scripts/offline/install_offline.sh" "$STAGE/scripts/install_offline.sh"
chmod 0755 "$STAGE/scripts/install.sh" "$STAGE/scripts/install_offline.sh"

COMMIT="${GRE_PANEL_BUILD_COMMIT:-$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="${GRE_PANEL_BUILD_DATE:-$(git -C "$REPO_ROOT" show -s --format=%cI HEAD 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)}"
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

step "Writing manifest.json"
{
  printf '{\n'
  printf '  "name": "tunnel-panel",\n'
  printf '  "application": "gre-panel",\n'
  printf '  "version": "%s",\n' "$VERSION"
  printf '  "commit": "%s",\n' "$COMMIT"
  printf '  "repository": "https://github.com/DrSaeedHub/Tunnel-Panel",\n'
  printf '  "built_at": "%s",\n' "$BUILT_AT"
  printf '  "source_date": "%s",\n' "$BUILD_DATE"
  printf '  "ubuntu_version": "%s",\n' "$UBUNTU"
  printf '  "ubuntu_codename": "%s",\n' "$HOST_CODENAME"
  printf '  "architecture": "%s",\n' "$ARCH"
  printf '  "bundle_type": "%s",\n' "$FLAVOR"
  printf '  "installer_schema": 1,\n'
  printf '  "packaging": "static Go binaries built online; OS packages as a local flat APT repository",\n'
  printf '  "runtime": "single static binary (CGO disabled); no libc or interpreter dependency",\n'
  printf '  "glibc_constraint": "none; the binaries are statically linked",\n'
  printf '  "build_host": "ubuntu-%s %s",\n' "$HOST_VERSION" "$HOST_ARCH"
  printf '  "artifacts": ["dist/release/%s/%s", "dist/release/%s/%s"],\n' "$VERSION" "$BINARY" "$VERSION" "$CLI"
  printf '  "packages": [\n'
  awk '/^Package: /{p=$2} /^Version: /{v=$2; printf "    {\"name\": \"%s\", \"version\": \"%s\"},\n", p, v}' \
    "$STAGE/apt-repo/Packages" | sed '$ s/,$//'
  printf '  ]\n'
  printf '}\n'
} > "$STAGE/manifest.json"

step "Writing README_OFFLINE.md"
FLAVOR_LINE="a normal Ubuntu Server installation"
[[ "$FLAVOR" == "bootstrap" ]] && FLAVOR_LINE="a minimal Ubuntu installation; it carries the full dependency closure of every required OS package"
cat > "$STAGE/README_OFFLINE.md" <<EOF
# GRE Tunnel Panel — offline bundle

| | |
|---|---|
| Ubuntu release | **$UBUNTU only** (codename $HOST_CODENAME) |
| Architecture | **$ARCH only** |
| Bundle type | **$FLAVOR** — for $FLAVOR_LINE |
| Panel version | $VERSION (commit $COMMIT) |

Installation needs **no internet access**. Everything the installer touches —
the panel binary, the \`tnp\` management CLI, and any missing OS packages —
is inside this bundle, and the installer verifies the bundle's SHA-256
manifest before it changes anything on the system.

## Install

\`\`\`
# 1. Transfer the bundle to the server by any method you prefer.

# 2. Extract it:
tar -xzf $BUNDLE_NAME.tar.gz

# 3. Enter the extracted directory:
cd $BUNDLE_NAME

# 4. Start the offline installer:
sudo ./scripts/install_offline.sh
\`\`\`

The installer prompts for the admin username, the password, the port and the
web path, proposing a randomly generated port and web path — the same flow as
the online installer. On a server that already has the panel it offers
upgrade, repair and uninstall instead of asking first-run questions.

## Non-interactive

\`\`\`
sudo ./scripts/install_offline.sh --non-interactive --json \\
  --username admin --password 'chosen-password' --port 8443 --web-path secret123
\`\`\`

## Upgrade an existing installation

\`\`\`
sudo ./scripts/install_offline.sh --upgrade --yes
\`\`\`

The database, settings, accounts and tunnels are preserved.

## Repair

\`\`\`
sudo ./scripts/install_offline.sh --repair --yes
\`\`\`

Reinstalls the binaries from this bundle, restores the systemd unit and the
environment file if either is missing, repairs data-directory permissions,
reinstalls any missing OS packages from the bundled repository, restarts the
service and verifies it answers. Data is never touched.

## Uninstall

\`\`\`
sudo ./scripts/install_offline.sh --uninstall
\`\`\`

Asks separately about the tunnels (live traffic) and the database before
deleting either; both are kept by default. To remove everything, including
the database, the tunnels and the \`tnp\` CLI:

\`\`\`
sudo ./scripts/install_offline.sh --full-uninstall
\`\`\`

which still confirms before deleting, or with \`--yes\` for automation.

## After installation

| | |
|---|---|
| Service status | \`systemctl status gre-panel\` |
| Logs | \`journalctl -u gre-panel -n 50\` |
| Install log | \`/var/log/gre-panel-offline-install.log\` |
| Configuration seed | \`/etc/gre-panel.env\` |
| Database and data | \`/var/lib/gre-panel/\` |
| Management CLI | \`tnp\` |

## Choosing a bundle

Each bundle fits exactly one Ubuntu release and one architecture; the
installer checks and refuses a mismatch. \`standard\` bundles fit a normal
Ubuntu Server installation. \`bootstrap\` bundles additionally carry the full
dependency closure of the required OS packages, for minimal installations.
This bundle is **ubuntu$UBUNTU / $ARCH / $FLAVOR**.
EOF

# ------------------------------------------------------------------ integrity

step "Writing checksums.sha256"
(
  cd "$STAGE"
  find . -type f ! -name checksums.sha256 | sed 's|^\./||' | LC_ALL=C sort |
    xargs sha256sum > checksums.sha256
  sha256sum --check --quiet checksums.sha256
)

# ------------------------------------------------------------------- tarball

TARBALL="$OUTPUT/$BUNDLE_NAME.tar.gz"
step "Packing $TARBALL"
tar --sort=name --owner=0 --group=0 --numeric-owner \
  --mtime="$BUILD_DATE" \
  -C "$WORK/stage" -cf - "$BUNDLE_NAME" | gzip -9 -n > "$TARBALL"
sha256sum "$TARBALL" | sed "s|$OUTPUT/||" > "$TARBALL.sha256"

# Verified the way an operator's machine will read it: extracted fresh, and
# the internal manifest checked again. A tarball that lists is not yet a
# tarball that restores.
step "Verifying the packed bundle"
VERIFY="$(mktemp -d)"
trap 'rm -rf "$VERIFY"' EXIT
tar -xzf "$TARBALL" -C "$VERIFY"
(
  cd "$VERIFY/$BUNDLE_NAME"
  sha256sum --check --quiet checksums.sha256
  bash -n scripts/install_offline.sh
  bash -n scripts/install.sh
  [[ -f manifest.json && -f README_OFFLINE.md && -f apt-repo/Packages && -f apt-repo/Release ]]
)

SIZE="$(stat -c%s "$TARBALL")"
step "Done: $TARBALL ($((SIZE / 1024 / 1024)) MB, $DEB_COUNT packages)"
printf '%s\n' "$TARBALL"
