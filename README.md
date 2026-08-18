# GRE Tunnel Panel

A web panel for creating and operating GRE tunnels on a Linux server, distributed as a
**single static binary** — the React frontend is compiled into it, so installing it is a
download and a systemd unit. No interpreter, no virtualenv, no package manager.

The panel is installed independently on each server and runs as root, because creating a
tunnel means configuring kernel networking.

## Highlights

- **Tunnels** — create, edit, enable, disable, restart, reapply and delete GRE tunnels.
  Every change is previewed before it runs — the exact commands, the exact unit file, the
  rollback if a step fails — and is only reported successful once the backend has verified
  the result against the kernel. Nothing is reported working just because a command exited
  zero.
- **Pairing** — a tunnel's configuration travels to the other server as a pairing code, with
  the side flipped automatically, so the two ends can't disagree by a typo.
- **Monitoring** — native ICMP probing with no subprocess: one socket per tunnel bound to its
  own address, a rolling window in which a late reply revises a loss verdict, and a state
  machine with hysteresis so a single dropped packet doesn't flap a tunnel.
- **Diagnostics** — an analysis that reaches a specific verdict with the evidence behind it,
  a high-precision manual probe that streams packet by packet and is cancellable mid-run, and
  a path-MTU search that reports what it found and applies the recommendation.
- **Metrics** — CPU including steal time, memory derived from available, swap, disk, and
  per-interface throughput and volume, all read straight from `/proc` and `/sys`.
- **Bilingual** — Farsi and English, complete, with genuine RTL and bidirectional isolation
  of every technical value. Adding a language needs no code change.

## Installation

```bash
bash <(curl -Ls https://raw.githubusercontent.com/DrSaeedHub/Tunnel-Panel/main/scripts/install.sh)
```

With no arguments, it prompts for the admin username, password, port and web path — proposing
a randomly generated port and web path so that accepting the defaults is the safe choice, not
the lazy one. The web path may be left empty, which serves the panel at the root.

Running the same line again once the panel is installed opens `tnp`, its management CLI,
instead of installing over the top. `--no-menu` forces a fresh install.

Fully unattended:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/DrSaeedHub/Tunnel-Panel/main/scripts/install.sh) \
  --non-interactive --json \
  --username admin --password '…' --port 8443 --web-path $(openssl rand -hex 12)
```

The panel is served at `https://<host>:<port>/<web-path>/`. Everything lives under that
prefix; anything outside it returns a bare 404 that gives no sign the panel is there.

<details>
<summary><strong>Installer flags</strong></summary>

| Flag | Meaning |
|---|---|
| `--username <str>` | Operator account created on first run |
| `--password <str>` | Its password (minimum 12 characters) |
| `--port <int>` | Port the panel listens on |
| `--web-path <str>` | Secret URL prefix; `[A-Za-z0-9._~-]` only |
| `--bind <ip>` | Address to bind (default `0.0.0.0`) |
| `--language <fa\|en>` | Initial interface language |
| `--version <tag>` | Release to install (default `latest`) |
| `--arch <amd64\|arm64>` | Override architecture detection |
| `--release-base <url>` | Where to fetch from; also accepts `file://` or a local path |
| `--non-interactive` | Never prompt; every required value must be supplied |
| `--json` | Machine-readable result on **stdout**; human output goes to stderr |
| `--yes`, `-y` | Skip the confirmation prompt |
| `--upgrade` | Upgrade in place, preserving the database, settings and tunnels |
| `--uninstall` | Remove the panel, leaving panel-managed tunnels running |
| `--purge-tunnels` | With `--uninstall`, also remove panel-managed tunnels |
| `-h`, `--help` | Usage |

`--non-interactive` never silently generates a password: if one is missing, it fails and names
the flag. Flags and prompts mix freely — anything given on the command line is not asked for
again.

</details>

<details>
<summary><strong>Exit codes</strong></summary>

| Code | Meaning |
|---:|---|
| 0 | Success |
| 10 | Not running as root |
| 11 | Unsupported OS or architecture |
| 12 | systemd not present or not the running init |
| 13 | The chosen port is already in use |
| 14 | Bad arguments |
| 15 | Download failed |
| 16 | Checksum verification failed |
| 17 | The service failed to start, or never answered |
| 18 | No outbound connectivity, and no way to download |

A failed or unverified download aborts **without touching an existing installation**, and the
success banner prints only after the health endpoint has actually answered — never on the
strength of `systemctl start` returning zero.

</details>

### What gets installed

| Path | Purpose |
|---|---|
| `/usr/local/bin/gre-panel` | The binary |
| `/var/lib/gre-panel/` | Database and JWT key, mode `0700` |
| `/etc/gre-panel.env` | Bind address, port, web path, mode `0600` |
| `/etc/systemd/system/gre-panel.service` | The unit |

The unit runs as root with `CAP_NET_ADMIN` and `CAP_NET_RAW` retained. `NoNewPrivileges`,
`ProtectHome`, `ProtectSystem=full` and `PrivateTmp` are all safe to keep. Four common
hardening directives would break tunnel management and are deliberately absent:
`PrivateNetwork` puts the panel in a namespace where the host's interfaces don't exist,
`ProtectSystem=strict` makes `/etc` read-only so no tunnel unit file can be written,
`ProtectKernelModules` stops `ip_gre` from autoloading on the first tunnel, and a capability
bounding set without `CAP_NET_ADMIN` can't create an interface at all.

## Offline installation

Self-contained bundles are published with each release for servers with no internet access,
one per Ubuntu release and installation profile:

| Bundle | For |
|---|---|
| `…-ubuntu22.04-amd64-standard.tar.gz` | Ubuntu 22.04, normal server installation |
| `…-ubuntu24.04-amd64-standard.tar.gz` | Ubuntu 24.04, normal server installation |
| `…-ubuntu22.04-amd64-bootstrap.tar.gz` | Ubuntu 22.04, minimal installation |
| `…-ubuntu24.04-amd64-bootstrap.tar.gz` | Ubuntu 24.04, minimal installation |

**standard** is for a normal, healthy Ubuntu Server. **bootstrap** additionally carries the
full dependency closure of every required OS package, for minimal installations. Match the
bundle to the server's Ubuntu release — the installer checks and refuses a mismatch. Both
flavors include a local APT repository, so no installation step reaches the network; the
bundle's SHA-256 manifest is verified before anything touches the system.

Download one from the [releases page](https://github.com/DrSaeedHub/Tunnel-Panel/releases),
transfer it to the server by any method you like, then:

```bash
tar -xzf tunnel-panel-<ver>-ubuntu24.04-amd64-standard.tar.gz
cd tunnel-panel-<ver>-ubuntu24.04-amd64-standard
sudo ./scripts/install_offline.sh
```

The prompts, flags and exit codes are the same as the online installer's. On a server that
already has the panel, a bare run offers upgrade, repair and uninstall; non-interactively,
`--upgrade --yes` upgrades in place preserving the database and tunnels, `--repair --yes`
restores binaries, unit, packages and permissions without touching data, `--uninstall` removes
the panel (asking separately about tunnels and the database), and `--full-uninstall` removes
everything after one explicit confirmation. Each bundle ships its own `README_OFFLINE.md`
with the exact instructions for the files inside it.

## Configuration

Bootstrap settings come from the environment (or flags of the same name); everything else is
configured in the panel itself and stored in the database.

| Variable | Default | Meaning |
|---|---|---|
| `GRE_PANEL_DATA_DIR` | `/var/lib/gre-panel` | Database, JWT key and lock file |
| `GRE_PANEL_DB_PATH` | `<data-dir>/panel.db` | Database file, if it belongs elsewhere |
| `GRE_PANEL_BIND_HOST` | `0.0.0.0` | Address to bind |
| `GRE_PANEL_BIND_PORT` | `8787` | Port to bind |
| `GRE_PANEL_WEB_PATH` | — | Secret URL prefix; everything is served under it |
| `GRE_PANEL_DEV_MODE` | `false` | Fake link manager, for running unprivileged |
| `GRE_PANEL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `GRE_PANEL_SYSTEMD_DIR` | `/etc/systemd/system` | Where tunnel units are written |
| `GRE_PANEL_NETWORKD_DIR` | `/etc/systemd/network` | Where networkd files are written |
| `GRE_PANEL_IP_BIN` | found on `PATH` | The `ip` binary |
| `GRE_PANEL_SYSTEMCTL_BIN` | found on `PATH` | The `systemctl` binary |

Run `gre-panel --help` for the full list, and `gre-panel --version` for the build stamp.

## Building from source

Requires Go 1.23 and Node 18 (the frontend pins Vite 5 and Tailwind 3, which is what Node 18
supports).

```bash
# Everything: frontend, then a static binary per architecture, then SHA256SUMS
scripts/build-release.sh --version v0.1.0

# The frontend on its own — needed once in a fresh checkout, since web/dist is
# generated rather than committed and the Go build embeds it
cd web/_app && npm ci && npm run build      # writes web/dist

# Just the binary, once web/dist exists
CGO_ENABLED=0 go build -trimpath ./cmd/gre-panel
```

`CGO_ENABLED=0` is what makes the binary static: the SQLite driver is pure Go, so nothing
links against libc. Until the frontend has been built, every Go package fails to compile
with `pattern all:dist: no matching files found` — that is `web/embed.go` reporting that
the bundle it embeds is not there yet.

The npm project lives in `web/_app` rather than `web/`. The underscore is load-bearing — the
Go tool ignores directories whose names begin with one, which keeps `node_modules` out of
`go build ./...`; some npm packages ship Go files of their own, and without it the Go build
would depend on whatever npm had installed.

## Running the tests

```bash
go test -race ./...                  # backend, including the ICMP and state-machine tests
cd web/_app && npm run typecheck     # TypeScript
cd web/_app && npm run lint          # ESLint
cd web/_app && npm test              # Vitest, including bidi isolation
```

## Development

```bash
GRE_PANEL_DEV_MODE=true GRE_PANEL_DATA_DIR=/tmp/grepd GRE_PANEL_WEB_PATH=dev \
  GRE_PANEL_BIND_PORT=8080 go run ./cmd/gre-panel
```

Development mode substitutes a fake link manager and a loopback ICMP dialer, so the panel
runs unprivileged with nothing to configure. Raw sockets and netlink both need root, so what
runs there is a simulation of the network, not the network itself.

## Layout

```
cmd/gre-panel/        entry point, flag and environment parsing, lifespan
internal/config       bootstrap configuration and web-path normalisation
internal/model        entity structs and the fixed lookup identifiers
internal/db           SQLite schema, pragmas and idempotent seeds
internal/settings     typed settings store; the frontend renders from its schema
internal/auth         argon2id, JWT, CSRF, rate limiting and lockout
internal/api          chi router, error envelope, SSE, static assets
internal/audit        audit writer with secret redaction
internal/exec         process runner; no shell, ever
internal/link         netlink link manager, and a fake for tests and dev mode
internal/validate     input and conflict validation, MTU advice
internal/alloc        address pool allocation
internal/safety       the invariants no flag can override
internal/persist      systemd and networkd rendering
internal/tunnel       the lifecycle pipeline: plan, apply, verify, roll back
internal/reconcile    drift detection and adoption
internal/monitor      native ICMP probing, the state machine, history
internal/metrics      /proc and /sys sampling, traffic counters
internal/diag         analysis, manual probe, path-MTU search, traceroute
web/embed.go          embeds web/dist into the binary
web/_app/             the React application
scripts/              installer and release build
```
