#!/usr/bin/env bash
#
# Confirm a built binary really is statically linked.
#
# This is the guarantee that lets one artefact be dropped onto both Ubuntu
# 22.04 and 24.04. The installer verifies a checksum, which proves the bytes
# arrived intact; it proves nothing about whether they will run.
#
# The check is deliberately in two parts, because neither alone is enough:
#
#   * `go version -m` reads the build settings recorded inside the binary, so it
#     answers for the artefact whatever host is asking. It is the portable half
#     and it is authoritative about CGO, which is what decides staticness here.
#   * `ldd` inspects the ELF itself and would catch a binary that is dynamic for
#     some reason the build settings do not describe. It only works when the
#     host can read that architecture.
#
# When ldd cannot analyse the file — cross-building on a different platform, or
# Git Bash on Windows, where ldd exists and answers "Exec format error" — the
# check is reported as SKIPPED and says why. It used to print that error and
# carry straight on to "Done", which reads as though something was verified.
#
#   scripts/check-static.sh <binary> [go-binary]
set -uo pipefail

# classify_ldd turns an ldd invocation into one of three answers. It takes the
# exit status and the combined output so it can be tested without an ELF file.
#
#   static      ldd looked at the file and found no dynamic dependencies
#   dynamic     ldd found dependencies, which for this project is a failure
#   unverified  ldd could not read the file at all, so it answered nothing
classify_ldd() {
  local status="$1" output="$2"

  # A dependency line is the unambiguous signal, whatever the exit status.
  if printf '%s' "$output" | grep -q '=>'; then
    printf 'dynamic'
    return
  fi
  # The two things a working ldd says about a static binary.
  if printf '%s' "$output" | grep -qE 'not a dynamic executable|statically linked'; then
    printf 'static'
    return
  fi
  # Anything else — "Exec format error", "cannot execute binary file", an empty
  # answer, a non-zero exit with nothing recognisable — means ldd did not manage
  # to inspect the file. That is not the same as finding it clean.
  printf 'unverified'
  return
  # (status is accepted for callers that want to log it; the classification
  # above does not need it, because a working ldd exits non-zero for a static
  # binary on some systems and zero on others.)
  echo "$status" >/dev/null
}

# cgo_disabled reports whether the binary records CGO_ENABLED=0, which is what
# makes this project's binaries static: the SQLite driver is pure Go, so with
# CGO off nothing links against libc.
cgo_disabled() {
  local target="$1" go_bin="${2:-go}"
  command -v "$go_bin" >/dev/null 2>&1 || return 2
  local settings
  settings="$("$go_bin" version -m "$target" 2>/dev/null)" || return 2
  printf '%s' "$settings" | grep -q 'CGO_ENABLED=0'
}

# Sourced for its functions by the test; run directly it checks one binary.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  target="${1:?usage: check-static.sh <binary> [go-binary]}"
  go_bin="${2:-go}"

  if cgo_disabled "$target" "$go_bin"; then
    printf '    build settings: CGO_ENABLED=0\n' >&2
  else
    case $? in
      2) printf '    build settings: UNVERIFIED (%s could not read the build info)\n' "$go_bin" >&2 ;;
      *) printf '    build settings: CGO is ENABLED, so this binary is not static\n' >&2
         exit 4 ;;
    esac
  fi

  if command -v ldd >/dev/null 2>&1; then
    ldd_output="$(ldd "$target" 2>&1)"
    ldd_status=$?
    case "$(classify_ldd "$ldd_status" "$ldd_output")" in
      dynamic)
        printf '    ldd: this binary has dynamic dependencies:\n' >&2
        printf '%s\n' "$ldd_output" >&2
        exit 4 ;;
      static)
        printf '    ldd: no dynamic dependencies\n' >&2 ;;
      unverified)
        printf '    ldd: SKIPPED, this host cannot inspect that binary (%s)\n' \
          "$(printf '%s' "$ldd_output" | head -n1)" >&2 ;;
    esac
  else
    printf '    ldd: SKIPPED, not installed on this host\n' >&2
  fi
fi
