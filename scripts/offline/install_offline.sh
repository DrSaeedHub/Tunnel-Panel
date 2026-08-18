#!/usr/bin/env bash
#
# GRE tunnel panel — offline installer.
#
# Runs from inside an extracted offline bundle and needs no network at any
# point: the panel binary, the tnp management CLI and any missing OS packages
# all come from the bundle, and the bundle's SHA-256 manifest is verified
# before anything on the system is touched.
#
# This script is a thin, careful wrapper around the same install.sh that the
# online one-liner runs, pointed at the bundle instead of at the release
# host — so the prompts, the flags, the defaults, the exit codes and the
# success banner are the ones already documented, not a second installer that
# drifts from the first.
#
# Usage, from the extracted bundle directory:
#   sudo ./scripts/install_offline.sh                 interactive
#   sudo ./scripts/install_offline.sh --non-interactive --json \
#        --username admin --password '...' --port 8443 --web-path abc123
#   sudo ./scripts/install_offline.sh --upgrade --yes
#   sudo ./scripts/install_offline.sh --repair --yes
#   sudo ./scripts/install_offline.sh --uninstall
#   sudo ./scripts/install_offline.sh --full-uninstall
set -Eeuo pipefail

# ---------------------------------------------------------------- exit codes
#
# The delegated codes are install.sh's own, bubbled through unchanged so
# tooling written against the README keeps working. The three new ones are
# conditions only an offline bundle can hit.
readonly EXIT_OK=0
readonly EXIT_NOT_ROOT=10
readonly EXIT_UNSUPPORTED_OS=11
readonly EXIT_BAD_ARGUMENTS=14
readonly EXIT_CHECKSUM_FAILED=16
readonly EXIT_SERVICE_FAILED=17
readonly EXIT_BUNDLE_DAMAGED=19
readonly EXIT_NO_DISK_SPACE=20
readonly EXIT_PACKAGES_FAILED=21

readonly SERVICE_NAME="gre-panel"
readonly BINARY_PATH="/usr/local/bin/gre-panel"
readonly DATA_DIR="/var/lib/gre-panel"
readonly UNIT_PATH="/etc/systemd/system/gre-panel.service"
readonly CLI_PATH="/usr/local/bin/tnp"
readonly DEFAULT_LOG_FILE="/var/log/gre-panel-offline-install.log"

BUNDLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ------------------------------------------------------------------- output
#
# Everything human-readable goes to stderr so --json owns stdout, exactly as
# in install.sh. Colours only when stderr is a terminal: this script's output
# is also a log file, and escape codes in a log help nobody.

if [[ -t 2 ]]; then
  C_STEP=$'\033[1;34m' C_WARN=$'\033[1;33m' C_FAIL=$'\033[1;31m' C_OFF=$'\033[0m'
else
  C_STEP="" C_WARN="" C_FAIL="" C_OFF=""
fi
say() { printf '%s\n' "$*" >&2; }
step() { printf '%s==>%s %s\n' "$C_STEP" "$C_OFF" "$*" >&2; }
warn() { printf '%swarning:%s %s\n' "$C_WARN" "$C_OFF" "$*" >&2; }
fail() {
  local code="$1"
  shift
  printf '%serror:%s %s\n' "$C_FAIL" "$C_OFF" "$*" >&2
  exit "$code"
}

on_error() {
  printf '%serror:%s install_offline.sh failed at line %s: %s\n' \
    "$C_FAIL" "$C_OFF" "$1" "$2" >&2
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

usage() {
  cat >&2 <<'USAGE'
Install the GRE tunnel panel from this offline bundle. No network is used.

Modes (default: install, or a menu when the panel is already installed):
  --upgrade            Upgrade in place, preserving data and tunnels
  --repair             Reinstall binaries, unit and packages; keep all data
  --uninstall          Remove the panel; asks about tunnels and the database
  --full-uninstall     Remove the panel, tunnels, database and the tnp CLI
                       (confirms first; --yes skips the confirmation)

Install options (the same flags the online installer takes):
  --username <str>     Operator account to create on first run
  --password <str>     Its password (12+ characters recommended)
  --port <int>         Port the panel listens on
  --web-path <str>     Secret URL prefix; pass '' to serve at the root
  --bind <ip>          Address to bind (default 0.0.0.0)
  --language <fa|en>   Initial interface language
  --non-interactive    Never prompt; every required value must be given
  --json               Print a machine-readable result on stdout
  --yes, -y            Do not ask for confirmation
  --purge-tunnels      With --uninstall, also remove panel-managed tunnels
  --purge-data         With --uninstall, also delete the panel database
  --remove-cli         With --uninstall, also remove the tnp CLI
  --no-menu            Skip the management menu on an installed host

Bundle options:
  --force-os           Proceed on an Ubuntu release this bundle was not
                       built for (the binaries are static and will run, but
                       bundled OS packages will not be installed)
  --skip-packages      Do not check or install OS packages from the bundle
  -h, --help           Show this message

Environment: GRE_PANEL_OFFLINE_LOG overrides the log file location;
GRE_PANEL_OFFLINE_SKIP_SPACE_CHECK=1 skips the free-disk check.

Exit codes: install.sh's documented set (0, 10-18), plus 19 bundle damaged
or incomplete, 20 not enough free disk space, 21 OS packages could not be
installed from the bundle repository.
USAGE
}

# ---------------------------------------------------------------- arguments
#
# Every flag is parsed here rather than passed through blind, for two
# reasons: a typo should produce this script's usage, not a failure three
# layers down; and the wrapper needs to know the mode and the interactivity
# to decide what to verify and whether it may prompt.

FORWARD=()
MODE="install"
NO_MENU="${GRE_PANEL_NO_MENU:-0}"
FORCE_OS=0
SKIP_PACKAGES=0
ARGUMENT_COUNT=$#

require_value() {
  local flag="$1" value="${2-}"
  if [[ -z "$value" || "$value" == --* ]]; then
    usage
    fail "$EXIT_BAD_ARGUMENTS" "$flag requires a value."
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --username|--password|--port|--bind|--language)
      require_value "$1" "${2-}"; FORWARD+=("$1" "$2"); shift 2 ;;
    --web-path)
      # Given-and-empty is an answer: --web-path '' asks for the root, and
      # install.sh distinguishes the two by argument count exactly as here.
      if (( $# < 2 )); then
        usage
        fail "$EXIT_BAD_ARGUMENTS" "--web-path requires a value; pass '' for none."
      fi
      FORWARD+=("$1" "$2"); shift 2 ;;
    --non-interactive|--json) FORWARD+=("$1"); shift ;;
    --yes|-y) FORWARD+=(--yes); shift ;;
    --upgrade) MODE="upgrade"; shift ;;
    --repair) MODE="repair"; shift ;;
    --uninstall) MODE="uninstall"; shift ;;
    --full-uninstall) MODE="full-uninstall"; shift ;;
    --purge-tunnels|--purge-data|--remove-cli) FORWARD+=("$1"); shift ;;
    --no-menu) NO_MENU=1; shift ;;
    --force-os) FORCE_OS=1; shift ;;
    --skip-packages) SKIP_PACKAGES=1; shift ;;
    --version|--release-base|--arch|--installer-url)
      # The bundle decides these. Accepting an override here would let one
      # flag silently turn an offline installation into a download.
      fail "$EXIT_BAD_ARGUMENTS" "$1 is fixed by the bundle and cannot be overridden by the offline installer." ;;
    -h|--help) usage; exit "$EXIT_OK" ;;
    *) usage; fail "$EXIT_BAD_ARGUMENTS" "Unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || fail "$EXIT_NOT_ROOT" "This installer must run as root. It configures kernel networking and a system service."

# ------------------------------------------------------------------ logging
#
# stderr is duplicated into a log file; stdout is left alone so --json still
# owns it. Passwords never reach stderr: the delegated prompts read with
# echo off, and this wrapper never prints a credential.

LOG_FILE="${GRE_PANEL_OFFLINE_LOG:-$DEFAULT_LOG_FILE}"
if touch "$LOG_FILE" 2>/dev/null; then
  chmod 0600 "$LOG_FILE" 2>/dev/null || true
  exec 2> >(tee -a "$LOG_FILE" >&2)
  printf '\n----- %s: install_offline.sh mode=%s bundle=%s -----\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$MODE" "$BUNDLE_ROOT" >> "$LOG_FILE"
else
  LOG_FILE=""
  warn "could not open a log file; continuing without one."
fi
if command -v logger >/dev/null 2>&1; then
  logger -t gre-panel-offline "starting: mode=$MODE bundle=$BUNDLE_ROOT" || true
fi

# ----------------------------------------------------------- bundle integrity
#
# Verified before anything else happens, uninstall included: a bundle that
# fails its own manifest is not a thing to run scripts out of as root.

case "$BUNDLE_ROOT" in
  *" "*) fail "$EXIT_BUNDLE_DAMAGED" "the bundle is extracted under a path containing spaces, which APT sources cannot express. Move it to a path without spaces." ;;
esac

[[ -f "$BUNDLE_ROOT/checksums.sha256" ]] || fail "$EXIT_BUNDLE_DAMAGED" "checksums.sha256 is missing; this is not a complete bundle."
[[ -f "$BUNDLE_ROOT/manifest.json" ]] || fail "$EXIT_BUNDLE_DAMAGED" "manifest.json is missing; this is not a complete bundle."

step "Verifying the bundle against its SHA-256 manifest"
if ! (cd "$BUNDLE_ROOT" && sha256sum --check --quiet checksums.sha256 >&2); then
  fail "$EXIT_CHECKSUM_FAILED" "the bundle does not match its checksum manifest. It is damaged or was tampered with; nothing was installed."
fi

manifest_field() {
  sed -n 's/.*"'"$1"'":[[:space:]]*"\([^"]*\)".*/\1/p' "$BUNDLE_ROOT/manifest.json" | head -n1
}
BUNDLE_VERSION="$(manifest_field version)"
BUNDLE_UBUNTU="$(manifest_field ubuntu_version)"
BUNDLE_ARCH="$(manifest_field architecture)"
BUNDLE_TYPE="$(manifest_field bundle_type)"
[[ -n "$BUNDLE_VERSION" && -n "$BUNDLE_UBUNTU" && -n "$BUNDLE_ARCH" ]] ||
  fail "$EXIT_BUNDLE_DAMAGED" "manifest.json does not name a version, Ubuntu release and architecture."

RELEASE_BASE="$BUNDLE_ROOT/dist/release"
DELEGATE="$BUNDLE_ROOT/scripts/install.sh"
[[ -f "$DELEGATE" ]] || fail "$EXIT_BUNDLE_DAMAGED" "the bundled install.sh is missing."
[[ -f "$RELEASE_BASE/$BUNDLE_VERSION/gre-panel-linux-$BUNDLE_ARCH" ]] ||
  fail "$EXIT_BUNDLE_DAMAGED" "the bundled panel binary is missing."

# ------------------------------------------------------------- compatibility
#
# The manifest says what this bundle was built and tested for; the host says
# what it is. An architecture mismatch is fatal — the binaries cannot execute.
# A release mismatch is fatal by default because the bundled OS packages
# belong to one release's package universe; --force-os is the measured
# override for an operator who knows no packages will be needed.

[[ -r /etc/os-release ]] || fail "$EXIT_UNSUPPORTED_OS" "/etc/os-release is missing; this does not look like a supported Linux system."
HOST_ID="$(. /etc/os-release && printf '%s' "$ID")"
HOST_VERSION="$(. /etc/os-release && printf '%s' "$VERSION_ID")"
HOST_CODENAME="$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-unknown}")"

if command -v dpkg >/dev/null 2>&1; then
  HOST_ARCH="$(dpkg --print-architecture)"
else
  case "$(uname -m)" in
    x86_64) HOST_ARCH="amd64" ;;
    aarch64) HOST_ARCH="arm64" ;;
    *) HOST_ARCH="$(uname -m)" ;;
  esac
fi

step "Host: $HOST_ID $HOST_VERSION ($HOST_CODENAME), $HOST_ARCH, kernel $(uname -r)"
step "Bundle: tunnel-panel $BUNDLE_VERSION for ubuntu$BUNDLE_UBUNTU/$BUNDLE_ARCH ($BUNDLE_TYPE)"

if [[ "$HOST_ARCH" != "$BUNDLE_ARCH" ]]; then
  fail "$EXIT_UNSUPPORTED_OS" "this bundle carries $BUNDLE_ARCH binaries and packages; this host is $HOST_ARCH. You need the $HOST_ARCH bundle for Ubuntu $HOST_VERSION."
fi
if [[ "$HOST_ID" != "ubuntu" || "$HOST_VERSION" != "$BUNDLE_UBUNTU" ]]; then
  if [[ $FORCE_OS -eq 1 ]]; then
    warn "this bundle was built for Ubuntu $BUNDLE_UBUNTU and this host is $HOST_ID $HOST_VERSION."
    warn "--force-os: continuing. The static binaries will run, but the bundled"
    warn "OS packages belong to Ubuntu $BUNDLE_UBUNTU and will not be installed."
    SKIP_PACKAGES=1
  else
    fail "$EXIT_UNSUPPORTED_OS" "this bundle was built for Ubuntu $BUNDLE_UBUNTU on $BUNDLE_ARCH; this host is $HOST_ID $HOST_VERSION. Use the tunnel-panel bundle named ubuntu$HOST_VERSION-$HOST_ARCH, or pass --force-os if you accept that no OS packages can be installed."
  fi
fi

# ------------------------------------------------------------------ the menu
#
# A bare ./scripts/install_offline.sh on a host that already has the panel is
# almost never a request to reinstall it — the same reasoning as the online
# installer's handover to tnp, which cannot trigger here because the wrapper
# always passes arguments down. So the choice is offered at this level
# instead, in the same spirit: any argument means the caller said what they
# wanted, and gets it.

EXISTING_INSTALL=0
[[ -x "$BINARY_PATH" || -f "$UNIT_PATH" ]] && EXISTING_INSTALL=1

if [[ "$MODE" == "install" && $EXISTING_INSTALL -eq 1 && $ARGUMENT_COUNT -eq 0 && "$NO_MENU" != "1" ]]; then
  [[ -e /dev/tty ]] || fail "$EXIT_BAD_ARGUMENTS" "the panel is already installed and there is no terminal to choose an action on. Pass --upgrade, --repair or --uninstall."
  say ""
  say "The panel is already installed on this server."
  say ""
  say "  1) Upgrade to $BUNDLE_VERSION (keeps data, settings and tunnels)"
  say "  2) Repair this installation (keeps everything; restores files)"
  say "  3) Uninstall"
  say "  4) Uninstall completely (also tunnels, database and the tnp CLI)"
  if [[ -x "$CLI_PATH" ]]; then
    say "  5) Open the tnp management CLI"
  fi
  say "  q) Cancel"
  say ""
  read -r -p "Choice: " choice </dev/tty
  case "$choice" in
    1) MODE="upgrade" ;;
    2) MODE="repair" ;;
    3) MODE="uninstall" ;;
    4) MODE="full-uninstall" ;;
    5) [[ -x "$CLI_PATH" ]] || fail "$EXIT_BAD_ARGUMENTS" "tnp is not installed here."
       exec "$CLI_PATH" ;;
    q|Q|"") say "Nothing was changed."; exit "$EXIT_OK" ;;
    *) fail "$EXIT_BAD_ARGUMENTS" "that was not one of the choices." ;;
  esac
fi

# --------------------------------------------------------------- disk space
#
# Checked before anything is installed, not discovered halfway through. The
# requirement is modest — binaries plus a margin for any packages apt
# unpacks — and the check can be waived deliberately, never accidentally.

if [[ "$MODE" != "uninstall" && "$MODE" != "full-uninstall" && "${GRE_PANEL_OFFLINE_SKIP_SPACE_CHECK:-0}" != "1" ]]; then
  bundle_kb="$(du -sk "$BUNDLE_ROOT" 2>/dev/null | awk '{print $1}')"
  needed_kb=$((bundle_kb + 200 * 1024))
  for mount in /usr/local /var/lib; do
    available_kb="$(df --output=avail -k "$mount" 2>/dev/null | tail -n1 | tr -d ' ')"
    [[ -n "$available_kb" ]] || continue
    if (( available_kb < needed_kb )); then
      fail "$EXIT_NO_DISK_SPACE" "$mount has $((available_kb / 1024)) MB free and the installation needs about $((needed_kb / 1024)) MB. Free some space, or set GRE_PANEL_OFFLINE_SKIP_SPACE_CHECK=1 to proceed anyway."
    fi
  done
fi

# ---------------------------------------------------------------- packages
#
# Only what is missing is installed, and only from the bundle: apt is pointed
# at the bundled repository through its own configuration overrides, so the
# system's real sources — and therefore the network — are never consulted.
# On a normal server every one of these commands already exists and this
# section does nothing at all.

APT_STATE=""
cleanup() { if [[ -n "$APT_STATE" ]]; then rm -rf "$APT_STATE"; fi; }
trap cleanup EXIT

offline_apt() {
  DEBIAN_FRONTEND=noninteractive apt-get \
    -o Dir::Etc::sourcelist="$APT_STATE/offline.list" \
    -o Dir::Etc::sourceparts="$APT_STATE/parts" \
    -o Dir::State::lists="$APT_STATE/lists" \
    -o Acquire::Retries=0 \
    "$@"
}

ensure_packages() {
  local missing=()
  command -v ip >/dev/null 2>&1 || missing+=(iproute2)
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    missing+=(curl)
  fi
  command -v openssl >/dev/null 2>&1 || missing+=(openssl)

  if (( ${#missing[@]} == 0 )); then
    step "All required OS packages are already installed"
    return 0
  fi

  step "Installing from the bundled package repository: ${missing[*]}"
  if ! command -v apt-get >/dev/null 2>&1; then
    # No apt at all is not a state a valid Ubuntu system is in, but dpkg can
    # still place the named packages. Dependencies must then already be
    # satisfied; if dpkg disagrees, that is a real fact about the host and
    # the answer is the bootstrap bundle plus a working apt, not a download.
    local pkg deb
    for pkg in "${missing[@]}"; do
      deb="$(find "$BUNDLE_ROOT/apt-repo" -maxdepth 1 -name "${pkg}_*.deb" | head -n1)"
      [[ -n "$deb" ]] || fail "$EXIT_PACKAGES_FAILED" "the bundle repository has no package for '$pkg'."
      dpkg -i "$deb" ||
        fail "$EXIT_PACKAGES_FAILED" "dpkg could not install $pkg; its dependencies are not present. Use the bootstrap bundle on a host with a working apt."
    done
    return 0
  fi

  APT_STATE="$(mktemp -d)"
  mkdir -p "$APT_STATE/parts" "$APT_STATE/lists"
  printf 'deb [trusted=yes] file:%s ./\n' "$BUNDLE_ROOT/apt-repo" > "$APT_STATE/offline.list"

  # [trusted=yes] is an accounted-for decision, not a shrug: the repository
  # is immutable, local, and every byte of it was just verified against the
  # bundle's SHA-256 manifest above.
  if ! offline_apt update >&2; then
    fail "$EXIT_PACKAGES_FAILED" "apt could not read the bundled repository at $BUNDLE_ROOT/apt-repo."
  fi
  if ! offline_apt install -y --no-install-recommends "${missing[@]}" >&2; then
    if [[ "$BUNDLE_TYPE" == "standard" ]]; then
      fail "$EXIT_PACKAGES_FAILED" "the standard bundle could not satisfy '${missing[*]}' on this host; a dependency is missing from the system. Use the bootstrap bundle, which carries the full dependency closure."
    fi
    fail "$EXIT_PACKAGES_FAILED" "the bundled repository could not satisfy '${missing[*]}'; the log at $LOG_FILE has apt's full answer."
  fi
}

if [[ "$MODE" != "uninstall" && "$MODE" != "full-uninstall" && $SKIP_PACKAGES -eq 0 ]]; then
  ensure_packages
fi

# ------------------------------------------------------------------ delegate
#
# From here the bundled install.sh does what it always does; the only
# difference an operator can observe is that the "Downloading" steps copy
# from the bundle instead of fetching. Its exit code is this script's.

run_delegate() {
  local rc=0
  bash "$DELEGATE" --release-base "$RELEASE_BASE" --version "$BUNDLE_VERSION" "$@" || rc=$?
  if (( rc == EXIT_SERVICE_FAILED )); then
    say ""
    warn "recent service log:"
    journalctl -u "$SERVICE_NAME" -n 25 --no-pager >&2 2>/dev/null || true
  fi
  if (( rc != 0 )); then
    [[ -n "$LOG_FILE" ]] && say "The full log is at $LOG_FILE."
    exit "$rc"
  fi
}

case "$MODE" in
  install)
    run_delegate "${FORWARD[@]}"
    ;;

  upgrade)
    run_delegate --upgrade "${FORWARD[@]}"
    ;;

  repair)
    # Repair is the upgrade path plus the things an upgrade assumes are
    # already right: the data directory's permissions, and the presence of
    # the unit and environment file — both of which the delegated installer
    # rewrites unconditionally. Data is never touched.
    if [[ $EXISTING_INSTALL -eq 0 && ! -d "$DATA_DIR" ]]; then
      fail "$EXIT_BAD_ARGUMENTS" "there is nothing here to repair: no binary, no unit and no data directory. Run the installer without --repair."
    fi
    step "Repairing the installation from the bundle"
    if [[ -d "$DATA_DIR" ]]; then
      chmod 0700 "$DATA_DIR" 2>/dev/null || true
      chown root:root "$DATA_DIR" 2>/dev/null || true
    fi
    run_delegate --upgrade "${FORWARD[@]}"
    step "Repair complete: binaries, unit and environment file restored from the bundle; data untouched."
    ;;

  uninstall)
    run_delegate --uninstall "${FORWARD[@]}"
    ;;

  full-uninstall)
    # Everything, in one named request — but still through the delegated
    # installer's own confirmation, so nothing is deleted silently.
    run_delegate --uninstall --purge-tunnels --purge-data --remove-cli "${FORWARD[@]}"
    ;;
esac

if [[ -n "$LOG_FILE" ]]; then
  say "The installation log is at $LOG_FILE."
fi
if command -v logger >/dev/null 2>&1; then
  logger -t gre-panel-offline "finished: mode=$MODE ok" || true
fi
exit "$EXIT_OK"
