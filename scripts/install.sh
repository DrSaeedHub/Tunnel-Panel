#!/usr/bin/env bash
#
# GRE tunnel panel installer.
#
# The panel is a single static Go binary with no runtime dependencies, so
# installing it is a download plus a systemd unit. There is no interpreter, no
# virtualenv and no package manager involved, and this script deliberately
# stays that simple.
#
# Usage:
#   bash <(curl -Ls https://example.invalid/install.sh)
#   bash <(curl -Ls https://example.invalid/install.sh) --non-interactive \
#        --username admin --password '...' --port 8443 --web-path abc123 --json
#
set -euo pipefail

# ---------------------------------------------------------------- exit codes
#
# Documented and distinct, so wrapper tooling can tell what went wrong without
# parsing prose.
readonly EXIT_OK=0
readonly EXIT_NOT_ROOT=10
readonly EXIT_UNSUPPORTED_OS=11
readonly EXIT_NO_SYSTEMD=12
readonly EXIT_PORT_IN_USE=13
readonly EXIT_BAD_ARGUMENTS=14
readonly EXIT_DOWNLOAD_FAILED=15
readonly EXIT_CHECKSUM_FAILED=16
readonly EXIT_SERVICE_FAILED=17
readonly EXIT_NO_CONNECTIVITY=18

readonly SERVICE_NAME="gre-panel"
readonly BINARY_PATH="/usr/local/bin/gre-panel"
readonly DATA_DIR="/var/lib/gre-panel"
readonly UNIT_PATH="/etc/systemd/system/gre-panel.service"
readonly ENV_PATH="/etc/gre-panel.env"
# The management CLI, installed beside the panel. It is what an operator gets
# when they run this script again on a host that already has it, and it is the
# only thing on the system that can change the panel's port or reset a password
# when nobody can log in.
readonly CLI_NAME="tnp"
readonly CLI_PATH="/usr/local/bin/tnp"
readonly SUPPORT_DIR="/usr/local/share/gre-panel"
readonly CACHED_INSTALLER="$SUPPORT_DIR/install.sh"
readonly CLI_ENV_PATH="$SUPPORT_DIR/cli.env"
# The backend refuses anything shorter, so the installer refuses it too rather
# than creating an account the panel will reject. Twelve is advice, said once
# where the password is chosen and never enforced.
readonly MIN_PASSWORD_LENGTH=1
readonly RECOMMENDED_PASSWORD_LENGTH=12
# The marker the panel writes into every file it generates. It is what tells a
# file the panel owns from one adopted from a previous setup, and it is the only
# safe way for --purge-tunnels to decide what is its to remove. Kept identical
# to persist.OwnershipMarker, which a test asserts.
readonly PANEL_FILE_MARKER="# gre-panel:managed=1"
readonly DEFAULT_RELEASE_BASE="https://github.com/DrSaeedHub/Tunnel-Panel/releases/download"
readonly DEFAULT_INSTALLER_URL="https://raw.githubusercontent.com/DrSaeedHub/Tunnel-Panel/main/scripts/install.sh"

# ---------------------------------------------------------------- arguments

USERNAME=""
PASSWORD=""
PORT=""
WEB_PATH=""
BIND_ADDRESS="0.0.0.0"
LANGUAGE=""
VERSION="latest"
ARCH=""
NON_INTERACTIVE=0
JSON_OUTPUT=0
ASSUME_YES=0
MODE="install"
PURGE_TUNNELS=0
# Removing the database is a separate decision from removing the tunnels.
# They used to be one flag, which meant an operator who wanted to keep their
# tunnels running also kept a database they were trying to discard, and one
# who wanted a clean database also tore down live traffic. Neither is what
# anyone asked for.
PURGE_DATA=0
RELEASE_BASE="${GRE_PANEL_RELEASE_BASE:-$DEFAULT_RELEASE_BASE}"

usage() {
  cat >&2 <<'USAGE'
Install the GRE tunnel panel.

  --username <str>     Operator account to create on first run
  --password <str>     Its password (12+ characters recommended)
  --port <int>         Port the panel listens on
  --web-path <str>     Secret URL prefix the panel is served under
  --bind <ip>          Address to bind (default 0.0.0.0)
  --language <fa|en>   Initial interface language
  --version <tag>      Release to install (default: latest)
  --arch <amd64|arm64> Override architecture detection
  --non-interactive    Never prompt; every required value must be given
  --json               Print a machine-readable result on stdout
  --yes                Do not ask for confirmation
  --upgrade            Upgrade in place, preserving data and tunnels
  --uninstall          Remove the panel, leaving tunnels running
  --purge-tunnels      With --uninstall, also remove panel-managed tunnels
  --purge-data         With --uninstall, also delete the panel database
  --remove-cli         With --uninstall, also remove the tnp management CLI
  --no-menu            Install even if tnp is present, instead of launching it
  --installer-url <u>  Where tnp fetches a fresh copy of this script from
  -h, --help           Show this message

Running this script with no arguments on a host that already has tnp installed
opens tnp instead of reinstalling. Pass --no-menu, or any other flag, to
install regardless. The web path may be empty: --web-path '' serves the panel
at the root.

Exit codes: 0 ok, 10 not root, 11 unsupported OS, 12 no systemd,
13 port in use, 14 bad arguments, 15 download failed, 16 checksum failed,
17 service failed to start, 18 no outbound connectivity.
USAGE
}

# Everything human-readable goes to stderr, so --json can own stdout entirely.
say() { printf '%s\n' "$*" >&2; }
step() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
fail() {
  local code="$1"
  shift
  printf '\033[1;31merror:\033[0m %s\n' "$*" >&2
  exit "$code"
}

require_value() {
  local flag="$1" value="${2-}"
  if [[ -z "$value" || "$value" == --* ]]; then
    usage
    fail "$EXIT_BAD_ARGUMENTS" "$flag requires a value."
  fi
}

# require_present is require_value for a flag whose value may legitimately be
# empty. --web-path '' is the request to serve the panel at the root, and
# require_value would reject it as a missing value — which it is not.
#
# $# is checked rather than the value itself: "the argument is absent" and "the
# argument is an empty string" are different, and only the shell's argument
# count can tell them apart.
require_present() {
  local flag="$1" count="$2"
  if (( count < 2 )); then
    usage
    fail "$EXIT_BAD_ARGUMENTS" "$flag requires a value; pass '' for none."
  fi
}

# Whether the operator named a web path at all, as opposed to leaving it out.
# An empty one is a choice and must not be re-prompted for.
WEB_PATH_GIVEN=0
# A database left behind by a previous uninstall already knows the port, the
# web path, the accounts, the tunnels and the rules. Asking for any of it
# again would be asking a question we have the answer to — and worse, a new
# answer would be ignored, because the panel takes its address from the
# database. The operator would be told one port and served on another.
REUSE_EXISTING_DATA=0
NO_MENU="${GRE_PANEL_NO_MENU:-0}"
REMOVE_CLI=0
INSTALLER_URL="${GRE_PANEL_INSTALLER_URL:-}"
ARGUMENT_COUNT=$#

while [[ $# -gt 0 ]]; do
  case "$1" in
    --username) require_value "$1" "${2-}"; USERNAME="$2"; shift 2 ;;
    --password) require_value "$1" "${2-}"; PASSWORD="$2"; shift 2 ;;
    --port) require_value "$1" "${2-}"; PORT="$2"; shift 2 ;;
    --web-path) require_present "$1" "$#"; WEB_PATH="$2"; WEB_PATH_GIVEN=1; shift 2 ;;
    --bind) require_value "$1" "${2-}"; BIND_ADDRESS="$2"; shift 2 ;;
    --language) require_value "$1" "${2-}"; LANGUAGE="$2"; shift 2 ;;
    --version) require_value "$1" "${2-}"; VERSION="$2"; shift 2 ;;
    --arch) require_value "$1" "${2-}"; ARCH="$2"; shift 2 ;;
    --release-base) require_value "$1" "${2-}"; RELEASE_BASE="$2"; shift 2 ;;
    --installer-url) require_value "$1" "${2-}"; INSTALLER_URL="$2"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --json) JSON_OUTPUT=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --upgrade) MODE="upgrade"; shift ;;
    --uninstall) MODE="uninstall"; shift ;;
    --purge-tunnels) PURGE_TUNNELS=1; shift ;;
    --purge-data) PURGE_DATA=1; shift ;;
    --remove-cli) REMOVE_CLI=1; shift ;;
    --no-menu) NO_MENU=1; shift ;;
    -h|--help) usage; exit "$EXIT_OK" ;;
    *) usage; fail "$EXIT_BAD_ARGUMENTS" "Unknown argument: $1" ;;
  esac
done

# ---------------------------------------------------------------- checks

[[ $EUID -eq 0 ]] || fail "$EXIT_NOT_ROOT" "This installer must run as root. It configures kernel networking and a system service."

# ------------------------------------------------------- hand over to the CLI
#
# Running this script again on a host that already has the panel is almost
# never a request to reinstall it. It is somebody who remembers one command and
# wants to change the port, reset a password, or see whether the thing is
# running. So a bare re-run opens tnp instead.
#
# Four conditions, and each one matters:
#
#   no arguments    --upgrade, --uninstall and every automated path must keep
#                   working exactly as they did. Any argument means the caller
#                   said what they wanted, and gets it.
#   tnp installed   there is nothing to hand over to otherwise.
#   panel installed the fourth condition, and it was missing. `uninstall
#                   --panel` leaves tnp in place by design, so a host that has
#                   removed the panel still has the CLI — and the handover then
#                   opened a management menu for a panel that was not there,
#                   announcing "the panel is already installed here" when it was
#                   not. There was no way back: the documented one-liner could
#                   never reinstall, because it handed over every time.
#   a terminal      the menu has nowhere to draw itself without one, and
#                   silently opening it in a pipeline would look like a hang.
#
# --no-menu and GRE_PANEL_NO_MENU=1 are the deliberate way past it, for
# reinstalling over a working installation. exec replaces this process, so
# tnp's exit code is the one the caller sees.
if (( ARGUMENT_COUNT == 0 )) && [[ "$NO_MENU" != "1" && -x "$CLI_PATH" && -x "$BINARY_PATH" ]]; then
  if [[ -e /dev/tty ]]; then
    say "The panel is already installed here, so this is opening $CLI_NAME."
    say "To install over it instead, run this script with --no-menu."
    say ""
    exec "$CLI_PATH"
  fi
fi

command -v systemctl >/dev/null 2>&1 || fail "$EXIT_NO_SYSTEMD" "systemd is required and systemctl was not found."
[[ -d /run/systemd/system ]] || fail "$EXIT_NO_SYSTEMD" "systemd is not the running init system."

[[ "$(uname -s)" == "Linux" ]] || fail "$EXIT_UNSUPPORTED_OS" "This panel runs on Linux only."

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64' ;;
    aarch64|arm64) printf 'arm64' ;;
    *) fail "$EXIT_UNSUPPORTED_OS" "Unsupported architecture: $(uname -m). Only amd64 and arm64 are published." ;;
  esac
}
[[ -n "$ARCH" ]] || ARCH="$(detect_arch)"
case "$ARCH" in
  amd64|arm64) ;;
  *) fail "$EXIT_BAD_ARGUMENTS" "--arch must be amd64 or arm64." ;;
esac

DOWNLOADER=""
if command -v curl >/dev/null 2>&1; then
  DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
  DOWNLOADER="wget"
fi

# Fetches a URL to a local path. A file:// source, or a bare absolute path, is
# copied rather than downloaded: the release host does not exist yet, and the
# whole flow has to be exercisable from a local directory without pretending to
# be one. The default source is still an ordinary release URL.
fetch() {
  local url="$1" destination="$2"
  case "$url" in
    file://*) cp -f "${url#file://}" "$destination" 2>/dev/null ;;
    /*) cp -f "$url" "$destination" 2>/dev/null ;;
    *)
      case "$DOWNLOADER" in
        curl) curl -fsSL --connect-timeout 15 --retry 2 -o "$destination" "$url" ;;
        wget) wget -q --timeout=15 --tries=3 -O "$destination" "$url" ;;
        *) return 1 ;;
      esac
      ;;
  esac
}

# Where one release artefact lives.
#
# A directory-served base — an offline bundle, a file:// path, a plain web host
# — is <base>/<version>/<file>. GitHub Releases is not: a tag is served under
# .../releases/download/<tag>/<file>, but the moving "latest" pointer is
# .../releases/latest/download/<file>, with the two segments swapped. Deciding
# the shape here, once, is what keeps `--version latest` from resolving to a
# 404 that would be reported as a download failure.
release_url() {
  local file="$1"
  if [[ "$VERSION" == "latest" && "$RELEASE_BASE" == */releases/download ]]; then
    printf '%s/latest/download/%s\n' "${RELEASE_BASE%/download}" "$file"
    return
  fi
  printf '%s/%s/%s\n' "$RELEASE_BASE" "$VERSION" "$file"
}

# True when the source needs the network at all.
source_is_remote() {
  case "$RELEASE_BASE" in
    file://*|/*) return 1 ;;
    *) return 0 ;;
  esac
}

# ---------------------------------------------------------------- validation
#
# Anything the operator actually supplied is checked here, before the script
# decides whether this is a fresh install or an upgrade. A password that is too
# short is a bad argument whichever it turns out to be, and reporting it as a
# download failure three steps later is no help at all.

validate_supplied() {
  if [[ -n "$PASSWORD" ]] && (( ${#PASSWORD} < MIN_PASSWORD_LENGTH )); then
    fail "$EXIT_BAD_ARGUMENTS" "--password must be at least $MIN_PASSWORD_LENGTH characters; the panel refuses anything shorter."
  fi
  if [[ -n "$PORT" ]]; then
    [[ "$PORT" =~ ^[0-9]+$ ]] || fail "$EXIT_BAD_ARGUMENTS" "--port must be a number."
    (( PORT > 0 && PORT < 65536 )) || fail "$EXIT_BAD_ARGUMENTS" "--port must be between 1 and 65535."
  fi
  # An empty web path is valid and means the panel is served at the root, so
  # only a non-empty one has characters to check.
  if [[ -n "$WEB_PATH" ]]; then
    [[ "$WEB_PATH" =~ ^[A-Za-z0-9._~-]+$ ]] ||
      fail "$EXIT_BAD_ARGUMENTS" "--web-path may contain only letters, digits, dot, underscore, tilde and hyphen. Pass '' to serve the panel at the root."
  fi
  if [[ -n "$LANGUAGE" && ! "$LANGUAGE" =~ ^[a-z]{2}(-[A-Za-z0-9]{2,8})?$ ]]; then
    fail "$EXIT_BAD_ARGUMENTS" "--language must be a language tag such as en or fa."
  fi
}
validate_supplied

# ---------------------------------------------------------------- uninstall

if [[ "$MODE" == "uninstall" ]]; then
  if [[ $ASSUME_YES -eq 0 ]]; then
    if [[ $NON_INTERACTIVE -eq 1 ]]; then
      fail "$EXIT_BAD_ARGUMENTS" "--uninstall without --yes needs a terminal to confirm on."
    fi
    say ""
    say "This removes the panel from this server."
    say ""
    # Two questions, because they are two decisions and the answers are usually
    # different: somebody removing the panel to reinstall it wants to keep both,
    # and somebody decommissioning a host wants neither.
    if [[ $PURGE_TUNNELS -eq 0 ]]; then
      say "Tunnels and forwarding rules are live traffic. Deleting them stops it."
      read -r -p "Delete the tunnels and forwarding rules this panel manages? [y/N] " reply </dev/tty
      [[ "$reply" =~ ^[Yy]$ ]] && PURGE_TUNNELS=1
    fi
    if [[ $PURGE_DATA -eq 0 ]]; then
      say ""
      say "The database holds the accounts, tunnels, rules, port and web path."
      say "Keep it and installing again brings all of that back, at the same address."
      read -r -p "Delete the panel database? [y/N] " reply </dev/tty
      [[ "$reply" =~ ^[Yy]$ ]] && PURGE_DATA=1
    fi
    say ""
    say "About to remove the panel:"
    if [[ $PURGE_TUNNELS -eq 1 ]]; then
      say "  tunnels and rules: DELETED"
    else
      say "  tunnels and rules: kept and still running"
    fi
    if [[ $PURGE_DATA -eq 1 ]]; then
      say "  database:          DELETED"
    else
      say "  database:          kept at $DATA_DIR"
    fi
    read -r -p "Continue? [y/N] " reply </dev/tty
    [[ "$reply" =~ ^[Yy]$ ]] || { say "Nothing was changed."; exit "$EXIT_OK"; }
  fi

  step "Stopping the service"
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  systemctl disable "$SERVICE_NAME" 2>/dev/null || true

  if [[ $PURGE_TUNNELS -eq 1 ]]; then
    # Panel-managed tunnels are exactly the ones whose files carry the panel's
    # ownership marker. Selecting by name cannot work: the panel names a unit
    # after its interface, so gre-a-1.service is indistinguishable by name from
    # a legacy unit adopted from a previous setup — and adopting one explicitly
    # promises not to take it over. The marker is what adoption itself uses to
    # decide whether a file is the panel's to rewrite, so it is used here too.
    step "Removing panel-managed tunnels"
    shopt -s nullglob
    for unit in /etc/systemd/system/*.service; do
      case "$(basename "$unit")" in
        "$SERVICE_NAME.service"|gre-panel-rules.service) continue ;;
      esac
      grep -q "$PANEL_FILE_MARKER" "$unit" 2>/dev/null || continue

      tunnel_unit="$(basename "$unit")"
      interface="${tunnel_unit%.service}"
      systemctl stop "$tunnel_unit" 2>/dev/null || true
      systemctl disable "$tunnel_unit" 2>/dev/null || true

      # The keepalive unit is the panel's too, and is named for the interface.
      keepalive="/etc/systemd/system/gre-panel-keepalive-$interface.service"
      if [[ -f "$keepalive" ]]; then
        systemctl stop "$(basename "$keepalive")" 2>/dev/null || true
        systemctl disable "$(basename "$keepalive")" 2>/dev/null || true
        rm -f "$keepalive"
      fi

      ip link del "$interface" 2>/dev/null || true
      rm -f "$unit"
    done

    # Tunnels persisted through networkd have no unit; they have a .netdev and
    # a .network carrying the same marker.
    for netdev in /etc/systemd/network/*.netdev; do
      grep -q "$PANEL_FILE_MARKER" "$netdev" 2>/dev/null || continue
      interface="$(basename "$netdev" .netdev)"
      ip link del "$interface" 2>/dev/null || true
      rm -f "$netdev" "/etc/systemd/network/$interface.network"
    done
    shopt -u nullglob
  else
    say "Tunnels and their unit files were left in place."
  fi

  # The database is removed on its own answer, not on the tunnels' one.
  if [[ $PURGE_DATA -eq 1 ]]; then
    rm -rf "$DATA_DIR"
    say "The panel database was deleted."
  else
    say "The panel database was kept at $DATA_DIR."
    say "Installing again restores the accounts, tunnels, rules, port and web path."
  fi

  rm -f "$UNIT_PATH" "$BINARY_PATH" "$ENV_PATH"
  systemctl daemon-reload

  # The CLI outlives the panel by default. Removing the panel and the tool that
  # reinstalls it in one step leaves an operator with neither, and the two are
  # separate requests: --remove-cli is how both are asked for.
  CLI_REMOVED=0
  if [[ $REMOVE_CLI -eq 1 ]]; then
    step "Removing the $CLI_NAME management CLI"
    rm -f "$CLI_PATH" "$CACHED_INSTALLER" "$CLI_ENV_PATH"
    rmdir "$SUPPORT_DIR" 2>/dev/null || true
    CLI_REMOVED=1
  elif [[ -x "$CLI_PATH" ]]; then
    say "The $CLI_NAME CLI was left at $CLI_PATH; remove it with '$CLI_NAME uninstall --cli --yes'."
  fi

  if [[ $JSON_OUTPUT -eq 1 ]]; then
    printf '{"action":"uninstall","purged_tunnels":%s,"removed_cli":%s,"service":"%s"}\n' \
      "$([[ $PURGE_TUNNELS -eq 1 ]] && echo true || echo false)" \
      "$([[ $CLI_REMOVED -eq 1 ]] && echo true || echo false)" "$SERVICE_NAME"
  fi
  step "The panel has been removed."
  exit "$EXIT_OK"
fi

# ---------------------------------------------------------------- gather input

random_port() {
  # A high port chosen at random is a better default than a memorable one: the
  # panel should not be where a scan expects it.
  local candidate
  for _ in $(seq 1 40); do
    candidate=$(( (RANDOM % 20000) + 20000 ))
    if ! port_in_use "$candidate"; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  printf '18080'
}

random_web_path() {
  # Proposed rather than left to the operator, so accepting the default is the
  # safe choice instead of the lazy one.
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 12
  else
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-24
  fi
}

port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -Hltn "sport = :$port" 2>/dev/null | grep -q . && return 0
    return 1
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$port\$" && return 0
    return 1
  fi
  # With neither tool the check cannot be made; the service start will catch it.
  return 1
}

prompt() {
  local label="$1" default="$2" answer=""
  read -r -p "$label [$default]: " answer </dev/tty || true
  printf '%s' "${answer:-$default}"
}

prompt_secret() {
  local label="$1" first="" second=""
  while :; do
    read -r -s -p "$label: " first </dev/tty || true
    printf '\n' >&2
    if (( ${#first} < MIN_PASSWORD_LENGTH )); then
      warn "The password must be at least $MIN_PASSWORD_LENGTH characters; $RECOMMENDED_PASSWORD_LENGTH or more is recommended."
      continue
    fi
    read -r -s -p "Confirm password: " second </dev/tty || true
    printf '\n' >&2
    if [[ "$first" != "$second" ]]; then
      warn "The two passwords do not match."
      continue
    fi
    printf '%s' "$first"
    return 0
  done
}

UPGRADE_EXISTING=0
if [[ -x "$BINARY_PATH" || -f "$UNIT_PATH" ]]; then
  UPGRADE_EXISTING=1
fi
[[ "$MODE" == "upgrade" ]] && UPGRADE_EXISTING=1

if [[ $UPGRADE_EXISTING -eq 1 ]]; then
  # An upgrade keeps the database, the settings and every tunnel, so none of
  # the first-run questions apply.
  step "An existing installation was found; upgrading in place"
  if [[ -f "$ENV_PATH" ]]; then
    # shellcheck disable=SC1090
    while IFS='=' read -r key value; do
      case "$key" in
        GRE_PANEL_BIND_PORT) PORT="${PORT:-$value}" ;;
        GRE_PANEL_WEB_PATH) WEB_PATH="${WEB_PATH:-$value}" ;;
        GRE_PANEL_BIND_HOST) BIND_ADDRESS="$value" ;;
      esac
    done < <(grep -E '^GRE_PANEL_' "$ENV_PATH" || true)
  fi
else
  if [[ $NON_INTERACTIVE -eq 1 ]]; then
    missing=()
    [[ -n "$USERNAME" ]] || missing+=("--username")
    [[ -n "$PASSWORD" ]] || missing+=("--password")
    [[ -n "$PORT" ]] || missing+=("--port")
    # Given-and-empty is an answer. Testing the value rather than whether it
    # was given would demand a web path from an operator who has just said they
    # want none, and there would be no way to say it.
    (( WEB_PATH_GIVEN )) || missing+=("--web-path")
    if (( ${#missing[@]} )); then
      # Never silently generate a password: an account nobody knows the
      # password to is worse than a failed install.
      fail "$EXIT_BAD_ARGUMENTS" "--non-interactive needs every value. Missing: ${missing[*]}"
    fi
  else
    [[ -t 0 || -e /dev/tty ]] || fail "$EXIT_BAD_ARGUMENTS" "No terminal to prompt on. Use --non-interactive with every flag."
    say ""
    say "Installing the GRE tunnel panel."
    say ""
    if [[ -f "$DATA_DIR/panel.db" && -z "$PORT" && $WEB_PATH_GIVEN -eq 0 ]]; then
      REUSE_EXISTING_DATA=1
      say "A panel database is already here, kept from a previous uninstall."
      say "Its accounts, tunnels and forwarding rules come back with it, and the"
      say "panel returns to the port and web path it was on."
      say "Delete $DATA_DIR first if you wanted a clean install."
      say ""
    fi

    if [[ $REUSE_EXISTING_DATA -eq 0 ]]; then
      [[ -n "$USERNAME" ]] || USERNAME="$(prompt 'Admin username' 'admin')"
      [[ -n "$PASSWORD" ]] || PASSWORD="$(prompt_secret "Admin password (${RECOMMENDED_PASSWORD_LENGTH}+ characters recommended)")"
      [[ -n "$PORT" ]] || PORT="$(prompt 'Panel port' "$(random_port)")"
    fi
    if (( WEB_PATH_GIVEN == 0 )) && (( REUSE_EXISTING_DATA == 0 )); then
      # A secret path is proposed rather than left blank, so accepting the
      # default is the safe choice. Typing "none" is how an operator asks for
      # the root, because an empty answer at a prompt with a default means
      # "keep the default" everywhere else in this script and it would be a
      # trap for it to mean something different here.
      say "The web path is a secret prefix the panel is served under."
      say "Type a value, or the word none to serve it at the root."
      WEB_PATH="$(prompt 'Web path' "$(random_web_path)")"
      [[ "${WEB_PATH,,}" == "none" ]] && WEB_PATH=""
      WEB_PATH_GIVEN=1
    fi
    if [[ $REUSE_EXISTING_DATA -eq 0 ]]; then
      [[ -n "$LANGUAGE" ]] || LANGUAGE="$(prompt 'Language (fa/en)' 'en')"
    fi
  fi

  # The prompts can have produced new values, so they are checked too.
  validate_supplied

  # Reusing a kept database means the port is not known yet: it is in that
  # database, and reading it needs the binary this script has not installed. So
  # there is nothing to check here, and checking anyway compared an empty string
  # against the listening sockets and refused the install with "Port  is already
  # in use". resolve_address fills PORT in once the binary is down, and a port
  # that turns out to be taken is handled where it can be — the panel falls back
  # to one that binds and reports that it did.
  if [[ $REUSE_EXISTING_DATA -eq 0 ]] && port_in_use "$PORT"; then
    fail "$EXIT_PORT_IN_USE" "Port $PORT is already in use. Choose another with --port."
  fi
fi

[[ -n "$LANGUAGE" ]] || LANGUAGE="en"

# ---------------------------------------------------------------- download

[[ -n "$DOWNLOADER" ]] || fail "$EXIT_NO_CONNECTIVITY" "Neither curl nor wget is installed, so the release cannot be downloaded."

if source_is_remote; then
  step "Checking outbound connectivity"
  [[ -n "$DOWNLOADER" ]] || fail "$EXIT_NO_CONNECTIVITY" "Neither curl nor wget is installed, so the release cannot be downloaded."
fi
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

RELEASE_URL="$(release_url "gre-panel-linux-$ARCH")"
CHECKSUM_URL="$RELEASE_URL.sha256"

step "Downloading gre-panel $VERSION ($ARCH)"
if ! fetch "$RELEASE_URL" "$STAGING/gre-panel"; then
  fail "$EXIT_DOWNLOAD_FAILED" "Could not download $RELEASE_URL. The existing installation was not touched."
fi

step "Verifying the checksum"
if ! fetch "$CHECKSUM_URL" "$STAGING/gre-panel.sha256"; then
  fail "$EXIT_DOWNLOAD_FAILED" "Could not download the checksum from $CHECKSUM_URL. Refusing to install an unverified binary."
fi

EXPECTED_SUM="$(awk '{print $1}' "$STAGING/gre-panel.sha256" | head -n1)"
ACTUAL_SUM="$(sha256sum "$STAGING/gre-panel" | awk '{print $1}')"
if [[ -z "$EXPECTED_SUM" || "$EXPECTED_SUM" != "$ACTUAL_SUM" ]]; then
  # An unverified download must never reach an existing installation.
  fail "$EXIT_CHECKSUM_FAILED" "Checksum mismatch. Expected $EXPECTED_SUM, got $ACTUAL_SUM. Nothing was installed."
fi

chmod 0755 "$STAGING/gre-panel"
if ! "$STAGING/gre-panel" --version >/dev/null 2>&1; then
  fail "$EXIT_DOWNLOAD_FAILED" "The downloaded binary did not run on this host."
fi

# ------------------------------------------------------------ the management CLI
#
# Fetched the same way and verified the same way. The two outcomes are
# deliberately not treated alike:
#
#   no checksum published  this release predates the CLI. Say so loudly and
#                          carry on: refusing would turn installing an older
#                          tag into a failure.
#   checksum mismatch      the download is not what it claims to be. That is
#                          fatal, exactly as it is for the panel.
#
# The distinction matters because "the artefact is absent" and "the artefact is
# wrong" are different facts and only one of them is a reason to stop.
CLI_URL="$(release_url "tnp-linux-$ARCH")"
CLI_AVAILABLE=0

step "Downloading the $CLI_NAME management CLI"
if fetch "$CLI_URL.sha256" "$STAGING/tnp.sha256" && [[ -s "$STAGING/tnp.sha256" ]]; then
  if ! fetch "$CLI_URL" "$STAGING/tnp"; then
    fail "$EXIT_DOWNLOAD_FAILED" "The CLI's checksum is published at $CLI_URL.sha256 but the binary at $CLI_URL could not be downloaded."
  fi
  CLI_EXPECTED="$(awk '{print $1}' "$STAGING/tnp.sha256" | head -n1)"
  CLI_ACTUAL="$(sha256sum "$STAGING/tnp" | awk '{print $1}')"
  if [[ -z "$CLI_EXPECTED" || "$CLI_EXPECTED" != "$CLI_ACTUAL" ]]; then
    fail "$EXIT_CHECKSUM_FAILED" "Checksum mismatch for the CLI. Expected $CLI_EXPECTED, got $CLI_ACTUAL. Nothing was installed."
  fi
  chmod 0755 "$STAGING/tnp"
  if ! "$STAGING/tnp" version >/dev/null 2>&1; then
    fail "$EXIT_DOWNLOAD_FAILED" "The downloaded $CLI_NAME did not run on this host."
  fi
  CLI_AVAILABLE=1
else
  warn "Release $VERSION does not publish the $CLI_NAME management CLI, so it will not be installed."
  warn "The panel itself is unaffected. Install a release that carries it to get $CLI_NAME."
fi

# ---------------------------------------------------------------- install

step "Installing to $BINARY_PATH"
install -m 0755 "$STAGING/gre-panel" "$BINARY_PATH"

install -d -m 0700 "$DATA_DIR"
install -d -m 0755 "$SUPPORT_DIR"

if [[ $CLI_AVAILABLE -eq 1 ]]; then
  step "Installing $CLI_NAME to $CLI_PATH"
  install -m 0755 "$STAGING/tnp" "$CLI_PATH"

  # A copy of this script, so uninstalling and reinstalling do not need the
  # network. The most likely reason somebody is uninstalling is that something
  # is already wrong, and requiring a download then is unkind.
  #
  # $0 is a real file when this was run as `bash install.sh`, and a consumed
  # pipe when it was run as `bash <(curl ...)`. Only the first can be copied;
  # in the second case tnp downloads a fresh copy when it needs one, which is
  # why it also records where from.
  if [[ -f "$0" ]] && cp -f "$0" "$CACHED_INSTALLER" 2>/dev/null; then
    chmod 0755 "$CACHED_INSTALLER"
  else
    rm -f "$CACHED_INSTALLER"
  fi

  # Where this installation came from, so `tnp update` fetches from the same
  # place rather than from a default that may point somewhere else.
  if [[ -z "$INSTALLER_URL" ]]; then
    case "$RELEASE_BASE" in
      # GitHub serves release assets and repository files from different hosts,
      # so the installer cannot be derived from the release base at all: it
      # comes from the repository itself.
      */releases/download) INSTALLER_URL="$DEFAULT_INSTALLER_URL" ;;
      # Anywhere else, it lives beside the release directory on the same host:
      # .../dist/release -> .../scripts/install.sh. A guess, so it is recorded
      # as one and --installer-url overrides it.
      *) INSTALLER_URL="${RELEASE_BASE%/dist/release}/scripts/install.sh" ;;
    esac
  fi
  umask 077
  cat > "$CLI_ENV_PATH" <<CLIENV
# Written by the installer so tnp knows where this installation came from.
GRE_PANEL_RELEASE_BASE=$RELEASE_BASE
GRE_PANEL_INSTALLER_URL=$INSTALLER_URL
GRE_PANEL_VERSION=$VERSION
CLIENV
  chmod 0644 "$CLI_ENV_PATH"
fi

# Every directory named in the unit's ReadWritePaths has to exist, or systemd
# refuses to set up the mount namespace and the service will not start at all.
# These are standard on any systemd host; creating them costs nothing and makes
# the unit safe on one where a directory happens to be absent.
install -d -m 0755 /etc/sysctl.d /etc/systemd/system /etc/systemd/network

# write_env_file exists as a function because when it runs depends on where the
# port comes from. Normally the values are known before the binary is installed
# and it runs here. Reusing a kept database, they are IN that database and
# cannot be read until the binary is down, so it runs after resolve_address
# instead — writing it here would have seeded an empty port, and the panel would
# then compare an empty seed against its stored value, decide the file had been
# edited, and serve somewhere nobody asked for.
write_env_file() {
  step "Writing $ENV_PATH"
  umask 077
  cat > "$ENV_PATH" <<ENV
# Read by systemd and handed to the panel at startup.
#
# GRE_PANEL_BIND_PORT and GRE_PANEL_WEB_PATH are a seed, not the last word. The
# panel stores where it serves in its own database, because it can write that
# and it cannot write this file — the unit runs with ProtectSystem=full, which
# makes /etc read-only to it. So a port changed from the panel or from tnp will
# not be reflected here unless tnp made the change.
#
# Editing a value here still works and is the way back in when nothing else is:
# the panel compares this file against what it said at the last start, and a
# difference is taken as an instruction. Change a line, restart the service, and
# the panel adopts it.
#
# 'tnp status' reports what is actually in effect, and says so when the two
# disagree. An empty GRE_PANEL_WEB_PATH means the panel is served at the root.
GRE_PANEL_DATA_DIR=$DATA_DIR
GRE_PANEL_BIND_HOST=$BIND_ADDRESS
GRE_PANEL_BIND_PORT=$PORT
GRE_PANEL_WEB_PATH=$WEB_PATH
GRE_PANEL_LANGUAGE=$LANGUAGE
ENV
  chmod 0600 "$ENV_PATH"
}

# resolve_address is defined here rather than lower down because bash resolves a
# function name at the point of call, not at the end of the file. It used to sit
# after its first caller, which made that call a plain "command not found" — the
# `if` took the failure branch every time, and the message said the database
# would not report a port when nothing had ever asked it.

# RESOLVE_ERROR carries why the last resolve_address failed. It used to discard
# stderr, so a failure here produced "the kept database would not report a port"
# and nothing at all about which of the four ways it could fail had happened.
RESOLVE_ERROR=""

resolve_address() {
  local json status
  RESOLVE_ERROR=""
  json="$("$BINARY_PATH" --print-address 2>/tmp/gre-panel-resolve.err)"
  status=$?
  if (( status != 0 )); then
    RESOLVE_ERROR="$(head -c 400 /tmp/gre-panel-resolve.err 2>/dev/null)"
    [[ -n "$RESOLVE_ERROR" ]] || RESOLVE_ERROR="the panel binary exited $status with no message"
    return 1
  fi
  if [[ -z "$json" ]]; then
    RESOLVE_ERROR="the panel binary printed nothing"
    return 1
  fi
  local resolved_port resolved_path
  resolved_port="$(printf '%s' "$json" | sed -n 's/.*"port"[[:space:]]*:[[:space:]]*\([0-9]\{1,\}\).*/\1/p' | head -n1)"
  resolved_path="$(printf '%s' "$json" | sed -n 's/.*"web_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  if [[ -z "$resolved_port" ]]; then
    RESOLVE_ERROR="the panel binary printed no port: $(printf "%s" "$json" | head -c 200)"
    return 1
  fi
  PORT="$resolved_port"
  WEB_PATH="$resolved_path"
  return 0
}


# Where the panel serves is settled before the environment file is written,
# because that file has to agree with it.
#
# resolve_address needs the binary and the database and nothing else — not a
# running service — so it runs here rather than after the start. It used to run
# after, which was fine while the file already existed and wrong the moment a
# reinstall had to write one: the unit has EnvironmentFile= without a leading
# dash, so systemd refuses to start at all when it is missing, and the panel
# never got far enough to be asked anything.
if [[ $REUSE_EXISTING_DATA -eq 1 || $UPGRADE_EXISTING -eq 1 ]]; then
  if resolve_address; then
    step "The panel is configured for port $PORT and web path '${WEB_PATH:-(root)}'"
  elif [[ $REUSE_EXISTING_DATA -eq 1 ]]; then
    fail "$EXIT_SERVICE_FAILED" "The kept database would not report a port: ${RESOLVE_ERROR:-no reason given}. Delete $DATA_DIR for a clean install."
  else
    warn "The panel could not report where it listens (${RESOLVE_ERROR:-no reason given}); using $ENV_PATH, which may be out of date."
  fi
fi

# Written on a first install, on a reinstall over a kept database, and on an
# upgrade that finds the file missing.
#
# That last case is not hypothetical: UPGRADE_EXISTING is set when the unit file
# OR the binary is present, and uninstall removes the environment file, so a
# host part-way between the two is an "upgrade" with nothing to read. The unit
# carries EnvironmentFile= with no leading dash, so systemd refuses to start at
# all and the panel never gets far enough to say why:
#
#   gre-panel.service: Failed to load environment files: No such file or directory
if [[ $UPGRADE_EXISTING -eq 0 || ! -f "$ENV_PATH" ]]; then
  write_env_file
fi

step "Installing the systemd unit"
cat > "$UNIT_PATH" <<UNIT
[Unit]
Description=GRE tunnel panel
Documentation=https://github.com/drs/gre-panel
# The panel binds a port and reads the routing table at startup, so it waits
# for the network to be configured rather than racing it.
After=network-online.target
Wants=network-online.target

[Service]
# Type=exec rather than simple: systemd then reports the unit as started only
# once the binary has actually been executed, so a missing or unrunnable
# binary fails the unit instead of appearing to start.
Type=exec
EnvironmentFile=$ENV_PATH
ExecStart=$BINARY_PATH
Restart=always
RestartSec=2s

# The panel creates GRE interfaces, writes unit files and probes with raw ICMP
# sockets, so it runs as root and keeps CAP_NET_ADMIN and CAP_NET_RAW.
#
# CAP_SYS_PTRACE is here for one specific safety invariant. The panel refuses to
# forward the port the live SSH daemon is on, and it finds that port by reading
# which process holds the listening socket, which means walking /proc/<pid>/fd
# for the socket's inode. That is a ptrace-mode read: being the same uid is not
# enough when the target holds capabilities the reader does not, and sshd holds
# the full set while this unit deliberately holds a handful. Without it the walk
# is denied for every process but the panel itself, and the panel concludes that
# nothing is listening on SSH. It then protects port 22 as a precaution, which
# is right on a stock host and wrong on one that moved SSH to 2222 — protected
# on the port nothing uses, forwardable on the port that locks you out. Measured
# on both hosts: without it SshPorts() is empty, with it the live port is found.
# CAP_DAC_READ_SEARCH is not sufficient; ptrace access is what is being checked.
User=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER CAP_SYS_MODULE CAP_SYS_PTRACE

# Hardening that is safe here:
#   NoNewPrivileges  - the panel never needs to gain privileges it did not start with
#   ProtectHome      - it has no business in /home, /root or /run/user
#   ProtectSystem=full - /usr, /boot AND /etc read-only. Everything the panel
#                      writes under /etc therefore has to be named in
#                      ReadWritePaths below; a directory that is not listed is
#                      read-only no matter that the panel runs as root.
#   PrivateTmp       - its temporary files are its own
#
# Hardening that would BREAK tunnel management, and is deliberately absent:
#   PrivateNetwork=yes        - would put the panel in its own netns, where the
#                               host's interfaces and routes do not exist
#   ProtectSystem=strict      - would make the whole filesystem read-only, /var
#                               included, so not even the database could be written
#   ProtectKernelModules=yes  - would stop ip_gre autoloading on first tunnel
#   RestrictAddressFamilies   - without AF_NETLINK and AF_PACKET there is no
#                               netlink and no raw ICMP probing
#   CapabilityBoundingSet without CAP_NET_ADMIN - no interface can be created
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=full
PrivateTmp=yes
# Every path the panel writes to. /etc/sysctl.d is here because the panel owns
# one file in it, 99-gre-panel.conf, which is how enabling IP forwarding
# survives a reboot: without the carve-out that write fails on a read-only
# filesystem and the forwarding switch can never be turned on from the panel.
ReadWritePaths=$DATA_DIR /etc/systemd/system /etc/systemd/network /etc/sysctl.d /run/systemd

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true

step "Starting the service"
systemctl restart "$SERVICE_NAME" || fail "$EXIT_SERVICE_FAILED" "systemctl could not start $SERVICE_NAME. Run: journalctl -u $SERVICE_NAME -n 50"

# ---------------------------------------------------------------- readiness
#
# The failure mode of the script this project replaces was printing success
# because systemctl returned zero. Success is claimed here only once the panel
# itself answers.

HEALTH_HOST="$BIND_ADDRESS"
[[ "$HEALTH_HOST" == "0.0.0.0" || "$HEALTH_HOST" == "::" ]] && HEALTH_HOST="127.0.0.1"

# base_path renders a web path as a URL prefix, and is the one place that knows
# an empty one means the root. Interpolating "$host:$port/$WEB_PATH/" directly
# produces a double slash the moment the path is empty, and http://host:8443//
# is not the URL the panel is serving.
base_path() {
  if [[ -z "${1-}" ]]; then printf '/'; else printf '/%s/' "$1"; fi
}

# Where the panel actually is, asked of the binary rather than assumed from the
# values written above.
#
# The port and the web path now live in the panel's database; the environment
# file seeds them on a first install and is an override afterwards. On an
# upgrade the two can legitimately differ — an operator may have moved the panel
# from the browser, which the panel can store and cannot write back to /etc —
# and polling the file's port would then health-check an address nothing is on
# and report a working panel as a failed install.



HEALTH_URL="http://$HEALTH_HOST:$PORT$(base_path "$WEB_PATH")api/v1/system/health"

step "Waiting for the panel to answer"
READY=0
for _ in $(seq 1 30); do
  if [[ "$DOWNLOADER" == "curl" ]]; then
    if curl -fsS --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; then READY=1; break; fi
  else
    if wget -q --timeout=3 -O /dev/null "$HEALTH_URL" 2>/dev/null; then READY=1; break; fi
  fi
  sleep 1
done

if [[ $READY -eq 0 ]]; then
  say ""
  systemctl status "$SERVICE_NAME" --no-pager -n 20 >&2 || true
  fail "$EXIT_SERVICE_FAILED" "The service started but the panel never answered at $HEALTH_URL."
fi

# ---------------------------------------------------------------- first account

if [[ $UPGRADE_EXISTING -eq 0 && $REUSE_EXISTING_DATA -eq 0 && -n "$USERNAME" ]]; then
  step "Creating the operator account"
  SETUP_URL="http://$HEALTH_HOST:$PORT$(base_path "$WEB_PATH")api/v1/auth/setup"
  SETUP_BODY="$(printf '{"username":%s,"password":%s}' \
    "$(printf '%s' "$USERNAME" | sed 's/\\/\\\\/g; s/"/\\"/g; s/^/"/; s/$/"/')" \
    "$(printf '%s' "$PASSWORD" | sed 's/\\/\\\\/g; s/"/\\"/g; s/^/"/; s/$/"/')")"

  if [[ "$DOWNLOADER" == "curl" ]]; then
    SETUP_STATUS="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$SETUP_URL" \
      -H 'Content-Type: application/json' -d "$SETUP_BODY" || true)"
  else
    SETUP_STATUS="$(wget -q -O /dev/null --server-response --method=POST \
      --header='Content-Type: application/json' --body-data="$SETUP_BODY" "$SETUP_URL" 2>&1 |
      awk '/HTTP\//{code=$2} END{print code}' || true)"
  fi

  case "$SETUP_STATUS" in
    200|201) ;;
    409) warn "An account already exists on this panel; the one given was not created." ;;
    *) warn "The account could not be created (HTTP ${SETUP_STATUS:-none}). Create it at the panel's first-run screen." ;;
  esac
fi

# ---------------------------------------------------------------- result

PUBLIC_HOST="$BIND_ADDRESS"
if [[ "$PUBLIC_HOST" == "0.0.0.0" || "$PUBLIC_HOST" == "::" ]]; then
  PUBLIC_HOST="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "$PUBLIC_HOST" ]] || PUBLIC_HOST="127.0.0.1"
fi
PANEL_URL="http://$PUBLIC_HOST:$PORT$(base_path "$WEB_PATH")"
INSTALLED_VERSION="$("$BINARY_PATH" --version 2>/dev/null | head -n1 | awk '{print $NF}')"
CLI_VERSION=""
[[ -x "$CLI_PATH" ]] && CLI_VERSION="$("$CLI_PATH" version 2>/dev/null | head -n1 | awk '{print $NF}')"

if [[ $JSON_OUTPUT -eq 1 ]]; then
  printf '{"action":"%s","url":"%s","port":%s,"web_path":"%s","served_at_root":%s,"username":"%s","service":"%s","version":"%s","architecture":"%s","cli_installed":%s,"cli_version":"%s","cli_path":"%s"}\n' \
    "$([[ $UPGRADE_EXISTING -eq 1 ]] && echo upgrade || echo install)" \
    "$PANEL_URL" "$PORT" "$WEB_PATH" \
    "$([[ -z "$WEB_PATH" ]] && echo true || echo false)" \
    "$USERNAME" "$SERVICE_NAME" "${INSTALLED_VERSION:-unknown}" "$ARCH" \
    "$([[ -x "$CLI_PATH" ]] && echo true || echo false)" "${CLI_VERSION:-}" "$CLI_PATH"
fi

say ""
step "The panel is running."
say ""
say "  URL:      $PANEL_URL"
if [[ -z "$WEB_PATH" ]]; then
  say "            (no web path: the panel is served at the root)"
fi
say "  Service:  $SERVICE_NAME"
say "  Data:     $DATA_DIR"
say "  Version:  ${INSTALLED_VERSION:-unknown} ($ARCH)"
if [[ -x "$CLI_PATH" ]]; then
  say "  Manage:   $CLI_NAME   (or run this installer again with no arguments)"
fi
say ""

case "$BIND_ADDRESS" in
  127.*|::1|localhost) ;;
  *)
    warn "The panel is bound to $BIND_ADDRESS and serves plain HTTP."
    warn "Passwords and session cookies will cross the network unencrypted."
    warn "Put a TLS-terminating reverse proxy in front of it, or bind to 127.0.0.1"
    warn "and reach it through an SSH tunnel."
    ;;
esac

exit "$EXIT_OK"
