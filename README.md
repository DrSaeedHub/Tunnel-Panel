<div align="center">

# Tunnel Panel

**GRE tunnels and port forwarding on a Linux server — from a web panel that shows its work.**

One static binary. No interpreter, no virtualenv, no package manager.
Every change is previewed before it runs and verified against the kernel after it does.

[![release](https://img.shields.io/github/v/release/DrSaeedHub/Tunnel-Panel?style=flat-square&color=6366f1&label=release)](https://github.com/DrSaeedHub/Tunnel-Panel/releases)
[![downloads](https://img.shields.io/github/downloads/DrSaeedHub/Tunnel-Panel/total?style=flat-square&color=22c55e&label=downloads)](https://github.com/DrSaeedHub/Tunnel-Panel/releases)
![platform](https://img.shields.io/badge/platform-linux%20%C2%B7%20amd64%20%C2%B7%20arm64-334155?style=flat-square)
![go](https://img.shields.io/badge/go-1.23-00ADD8?style=flat-square)
![runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-none-334155?style=flat-square)

[Install](#install) · [The tour](#the-tour) · [Feature reference](#feature-reference) · [Offline install](#offline-installation) · [Configuration](#configuration) · [Build from source](#building-from-source)

</div>

![The dashboard](docs/screenshots/02-dashboard.png)

<div align="center"><em>Every screenshot here is a live panel, loaded with demonstration data.</em></div>

## Install

```bash
bash <(curl -Ls https://raw.githubusercontent.com/DrSaeedHub/Tunnel-Panel/main/scripts/install.sh)
```

It asks for an admin username, a password, a port and a web path — proposing a random port and
a random web path, so accepting the defaults is the safe choice rather than the lazy one. Two
minutes later the panel is a systemd service at `https://<host>:<port>/<web-path>/`. Everything
lives under that prefix; anything outside it returns a bare 404 that gives no sign the panel is
there.

Running the same line again once the panel is installed opens **`tnp`**, its management CLI,
instead of installing over the top.

<details>
<summary><strong>Unattended installation, every flag, and the exit codes</strong></summary>

```bash
bash <(curl -Ls https://raw.githubusercontent.com/DrSaeedHub/Tunnel-Panel/main/scripts/install.sh) \
  --non-interactive --json \
  --username admin --password '…' --port 8443 --web-path $(openssl rand -hex 12)
```

| Flag | Meaning |
|---|---|
| `--username <str>` | Operator account created on first run |
| `--password <str>` | Its password |
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

| Code | Meaning | Code | Meaning |
|---:|---|---:|---|
| 0 | Success | 15 | Download failed |
| 10 | Not running as root | 16 | Checksum verification failed |
| 11 | Unsupported OS or architecture | 17 | The service never answered |
| 12 | systemd not present or not the init | 18 | No outbound connectivity |
| 13 | The chosen port is already in use | | |
| 14 | Bad arguments | | |

A failed or unverified download aborts **without touching an existing installation**, and the
success banner prints only after the health endpoint has actually answered — never on the
strength of `systemctl start` returning zero.

</details>

---

# The tour

## The whole server on one screen

CPU including steal time, memory derived from *available* rather than from *free*, swap, every
filesystem, and per-interface throughput and volume — read straight from `/proc` and `/sys`,
once a second, streamed over SSE. The fleet's health, the relay's throughput and the number of
connections crossing it are on the same screen, because they are the same question.

![Per-interface traffic breakdown](docs/screenshots/03-dashboard-traffic.png)

Each tunnel appears in the breakdown under the name you gave it, and clicking it goes there.

## Tunnels that are verified, not assumed

Create, edit, enable, disable, restart, reapply and delete GRE, GRETAP, IP6GRE and IP6GRETAP
tunnels. Nothing is reported working because a command exited zero: after every apply the panel
reads the interface back out of the kernel and checks it against what was asked for.

![The tunnel list](docs/screenshots/04-tunnels.png)

**Every change is previewed first** — the exact commands, the exact unit file that will be
written, the rollback that runs if a step fails, and the checks that will be made afterwards:

![The plan preview](docs/screenshots/11-tunnel-form-preview.png)

<details>
<summary><strong>The rest of a tunnel's configuration</strong></summary>

TTL, ToS, MTU with path-MTU discovery, GRE keys, input and output checksums and sequencing, the
DF bit, fwmark, transmit queue length, hop and encap limits, traffic class and flow label —
every one of them a field, with what the kernel will actually do spelled out beside it.

![Tunnel configuration](docs/screenshots/07-tunnel-configuration.png)

</details>

## The other end configures itself

A tunnel's configuration travels to the second server as a **pairing code** — as text or as a
QR code — with the side flipped automatically, so the two ends cannot disagree by a typo.

![Pairing code](docs/screenshots/09-pairing-code.png)

## Monitoring that does not flap

Native ICMP probing with no subprocess: one socket per tunnel bound to its own address, a
rolling window in which a late reply revises a loss verdict, and hysteresis so a single dropped
packet does not flip a tunnel to *down* and back. When ICMP is filtered but the path is fine,
the panel knocks on the far end over TCP and says so, rather than reporting a dead tunnel.

| A healthy tunnel | One that is losing packets |
|---|---|
| <img src="docs/screenshots/05-tunnel-detail.png" alt="A healthy tunnel"> | <img src="docs/screenshots/06-tunnel-degraded.png" alt="A degraded tunnel"> |

Latency and loss over the last hour, day, week or month; every state change kept as an event
with the reason that caused it; per-tunnel thresholds that override the global ones.

## Port forwarding, with failover that actually removes the backend

Relay any TCP or UDP port — or a whole port range — over a tunnel or straight out of the host.
Round-robin, source-hash or weighted balancing across several destinations; masquerade, SNAT or
no NAT at all; MSS clamping; per-source connection limits and connection rate limits; and
allowed source ranges kept in named lists you maintain once and point several rules at.

![Forwarding rules](docs/screenshots/11-routes.png)

**Failover is not a status badge.** The panel knocks on each destination on a schedule, and a
backend that stops answering is taken *out of the generated ruleset* and put back when it
answers again. The suppression is a column on the destination, so rebuilding the ruleset from
the records is the whole of what failover does:

![A destination taken out of the rotation](docs/screenshots/16-route-failover.png)

The rules the kernel holds are never a mystery. Every rule the panel writes carries a comment
naming the database row that generated it, so what is installed can be read back and matched —
and the panel says plainly when the kernel and the database disagree:

![The generated ruleset](docs/screenshots/14-route-generated-rules.png)

Everything the panel installs lives in **one** nftables table, or in its own iptables chains.
Rules belonging to Docker, firewalld or anything else live in their own tables and are never
read, flushed or reordered.

<details>
<summary><strong>What the destination sees, and the whole plan before it is applied</strong></summary>

Source rewriting is a decision with consequences, so it is offered as three sentences rather
than as a dropdown of NAT modes:

![The new rule form](docs/screenshots/22-route-form.png)

And the ruleset that would be submitted — in one transaction — is there before you commit to
it, with the files it writes, the rollback and the checks:

![The ruleset preview](docs/screenshots/23-route-form-preview.png)

</details>

## Every connection crossing the relay

Read over netlink from connection tracking: who connected, which destination took them, the
transport state, how old the connection is and how much has moved through it — filterable by
destination.

![Live connections](docs/screenshots/13-route-connections.png)

## Traffic limits, per direction

A limit on a tunnel, on a rule, or on a single destination. Received only, sent only, or both
together. Total, daily, weekly or monthly, with the window rolling over by rebasing rather than
by zeroing anything. **Warn** raises it in the interface; **enforce** takes the interface down
or rebuilds the ruleset without that destination — through the same code path your own click
would have used.

![A rule with a traffic limit](docs/screenshots/12-route-detail.png)

## Diagnostics that reach a verdict

Not a wall of output: an analysis that names what is wrong, with the evidence it collected and
what to try. Beside it, a high-precision manual probe that streams packet by packet and can be
cancelled mid-run, a path-MTU binary search that reports what it found and offers to apply it,
a traceroute, and a TCP knock on the far end.

![Diagnostics](docs/screenshots/08-tunnel-diagnostics.png)

A forwarding rule has its own: an analysis of the whole path, and a knock on every destination
at once — which also runs *before* a rule exists, so "create it and see" becomes an answer.

![Testing every destination](docs/screenshots/15-route-diagnostics.png)

## The kernel parameters a relay actually needs

A stock kernel is sized for a machine that serves a handful of connections at a time. A relay
is not that machine, and several of its limits are low enough to stop one outright — a full
conntrack table refuses every new connection on the host, SSH included. The panel reads what
this host holds, works out what it should be from its memory and core count, and writes the
difference to its own sysctl file: table size and timeouts, BBR and fq, backlogs, buffers, the
local port range, file descriptors — each one a field with the current value, the
recommendation, and a sentence explaining what it does.

![Kernel tuning](docs/screenshots/18-settings-tuning.png)

## Addressing, and the lists a rule admits

Point-to-point addresses come out of pools you define, allocated per tunnel, with the capacity
and the usage shown. Source lists are named sets of ranges — the panel ships a few — that any
number of rules can allow, edited in one place instead of retyped into every rule that needs
them.

| Address pools | Source lists |
|---|---|
| <img src="docs/screenshots/19-settings-pools.png" alt="Address pools"> | <img src="docs/screenshots/20-settings-source-lists.png" alt="Source lists"> |

Everything else is a typed setting with a default, a range and an explanation, rendered from the
backend's own schema — so the interface cannot drift from what the panel accepts.

## It fits on a phone

The panel is where an operator is, which at three in the morning is a phone.

<div align="center">
<img src="docs/screenshots/30-mobile-dashboard.png" alt="The dashboard on a phone" width="265">
<img src="docs/screenshots/31-mobile-tunnels.png" alt="Tunnels on a phone" width="265">
<img src="docs/screenshots/34-mobile-route-detail.png" alt="A forwarding rule on a phone" width="265">
</div>

## Farsi and English, dark and light

Complete Farsi with genuine RTL and bidirectional isolation of every technical value — an IP
address, a port range and a CIDR read correctly inside a right-to-left sentence, which is where
most translated panels come apart. Adding a language needs no code change.

| فارسی | Light |
|---|---|
| <img src="docs/screenshots/40-farsi-dashboard.png" alt="The panel in Farsi"> | <img src="docs/screenshots/21-dashboard-light.png" alt="The light theme"> |

---

# Feature reference

| | |
|---|---|
| **Tunnels** | GRE, GRETAP, IP6GRE, IP6GRETAP · create, edit, enable, disable, restart, reapply, delete · systemd, networkd or runtime persistence · plan preview with rollback and post-apply verification · pairing codes with the side flipped · drift detection and adoption of tunnels the panel did not create |
| **Addressing** | Address pools with capacity and usage · automatic per-tunnel allocation or manual addresses · several addresses per tunnel · overlap and conflict validation before anything is applied |
| **Monitoring** | Native ICMP, one socket per tunnel, no subprocess · rolling window with late-reply revision · hysteresis on state changes · TCP knock when ICMP is filtered · per-tunnel thresholds · history for an hour, a day, a week or a month · every transition kept with its reason |
| **Port forwarding** | TCP, UDP or both · single ports and port ranges · several destinations with round-robin, source-hash or weighted balancing · masquerade, SNAT or none · MSS clamping · per-source connection limits and connection rate limits · allowed source ranges and shared source lists · rule ordering that decides which rule wins |
| **Failover** | Scheduled TCP knock on every destination · a dead backend is removed from the generated ruleset and restored when it answers · failure and recovery thresholds · report-only mode when you want the alert without the action |
| **Accounting** | Per-rule and per-destination bytes and packets, folded across every ruleset rebuild · live connection table from conntrack over netlink · per-rule history for a day, a week or a month |
| **Traffic limits** | Scope: tunnel, rule or destination · direction: in, out or both · period: total, daily, weekly or monthly · warn or enforce |
| **Diagnostics** | Automated analysis with a verdict, evidence and a suggested fix · streaming manual ping, cancellable mid-run · path-MTU binary search with one-click apply · traceroute · TCP reachability check · every run kept |
| **Metrics** | CPU with steal time, load, memory, swap, disks, per-interface throughput and volume · one-second sampling streamed over SSE · lifetime totals that survive counter resets and reboots |
| **Kernel tuning** | Conntrack sizing and timeouts, congestion control, qdisc, backlogs, socket buffers, local port range, file descriptors — recommended from this host's memory and cores, written to the panel's own sysctl file, revertible |
| **Safety** | Refuses the changes that lock you out — the panel's own port, the live SSH port, the interface carrying the default route — and names the invariant that refused. Warnings can be overridden; refusals cannot |
| **Operations** | Audit log with secret redaction · backup and restore, including a one-time download link · update from inside the panel or with `tnp update` · panel port and web path changed from the panel, with a bind test and a fallback if the new port cannot be bound |
| **Interface** | Farsi and English with genuine RTL · dark and light · responsive down to a phone · keyboard shortcuts · every list searchable and filterable |

---

## Offline installation

Self-contained bundles are published with each release for servers with no internet access, one
per Ubuntu release and installation profile:

| Bundle | For |
|---|---|
| `…-ubuntu22.04-amd64-standard.tar.gz` | Ubuntu 22.04, normal server installation |
| `…-ubuntu24.04-amd64-standard.tar.gz` | Ubuntu 24.04, normal server installation |
| `…-ubuntu22.04-amd64-bootstrap.tar.gz` | Ubuntu 22.04, minimal installation |
| `…-ubuntu24.04-amd64-bootstrap.tar.gz` | Ubuntu 24.04, minimal installation |

**standard** is for a normal, healthy Ubuntu Server. **bootstrap** additionally carries the full
dependency closure of every required OS package, for minimal installations. Match the bundle to
the server's Ubuntu release — the installer checks and refuses a mismatch. Both flavors include
a local APT repository, so no installation step reaches the network; the bundle's SHA-256
manifest is verified before anything touches the system.

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
everything after one explicit confirmation. Each bundle ships its own `README_OFFLINE.md` with
the exact instructions for the files inside it.

## The `tnp` CLI

Installed alongside the panel, for the things you do from a shell:

```bash
tnp                 # the menu
tnp status          # service, port, web path, database, tunnels
tnp url             # where the panel is, including the web path
tnp update          # update to the latest release, keeping everything
tnp restart         # restart the service
tnp logs -n 200     # the last lines of the journal
tnp set-port 8443   # change the port, with a bind test first
tnp set-web-path …  # change the secret prefix
tnp set-username …  # rename the operator account
tnp reset-password  # when you are locked out
tnp backup          # write a backup file, or issue a one-time download link
tnp restore <file>  # restore one
tnp reinstall       # repair binaries, unit and permissions without touching data
tnp uninstall       # remove the panel; tunnels and database are asked about separately
```

## What gets installed

| Path | Purpose |
|---|---|
| `/usr/local/bin/gre-panel` | The panel |
| `/usr/local/bin/tnp` | The management CLI |
| `/var/lib/gre-panel/` | Database and JWT key, mode `0700` |
| `/etc/gre-panel.env` | Bind address, port, web path, mode `0600` |
| `/etc/systemd/system/gre-panel.service` | The unit |

The unit runs as root with `CAP_NET_ADMIN` and `CAP_NET_RAW` retained. `NoNewPrivileges`,
`ProtectHome`, `ProtectSystem=full` and `PrivateTmp` are all kept. Four common hardening
directives would break tunnel management and are deliberately absent: `PrivateNetwork` puts the
panel in a namespace where the host's interfaces do not exist, `ProtectSystem=strict` makes
`/etc` read-only so no tunnel unit file can be written, `ProtectKernelModules` stops `ip_gre`
from autoloading on the first tunnel, and a capability bounding set without `CAP_NET_ADMIN`
cannot create an interface at all.

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

`CGO_ENABLED=0` is what makes the binary static: the SQLite driver is pure Go, so nothing links
against libc. Until the frontend has been built, every Go package fails to compile with
`pattern all:dist: no matching files found` — that is `web/embed.go` reporting that the bundle
it embeds is not there yet.

The npm project lives in `web/_app` rather than `web/`. The underscore is load-bearing — the Go
tool ignores directories whose names begin with one, which keeps `node_modules` out of
`go build ./...`; some npm packages ship Go files of their own, and without it the Go build
would depend on whatever npm had installed.

### Running the tests

```bash
go test -race ./...                  # backend, including the ICMP and state-machine tests
cd web/_app && npm run typecheck     # TypeScript
cd web/_app && npm run lint          # ESLint
cd web/_app && npm test              # Vitest, including bidi isolation
```

### Development

```bash
GRE_PANEL_DEV_MODE=true GRE_PANEL_DATA_DIR=/tmp/grepd GRE_PANEL_WEB_PATH=dev \
  GRE_PANEL_BIND_PORT=8080 go run ./cmd/gre-panel
```

Development mode substitutes a fake link manager, a fake netfilter backend and a loopback ICMP
dialer, so the panel runs unprivileged with nothing to configure. Raw sockets and netlink both
need root, so what runs there is a simulation of the network, not the network itself.

## Layout

```
cmd/gre-panel/        entry point, flag and environment parsing, lifespan
cmd/tnp/              the management CLI
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
internal/persist      systemd, networkd and sysctl rendering
internal/tunnel       the lifecycle pipeline: plan, apply, verify, roll back
internal/reconcile    drift detection and adoption
internal/monitor      native ICMP probing, the state machine, history
internal/rules        nftables and iptables backends, rendering and read-back
internal/route        forwarding rules, destination probing, accounting, conntrack
internal/sourcelist   shared address lists
internal/quota        traffic limits and enforcement
internal/tuning       kernel parameters: recommendation, apply, revert
internal/metrics      /proc and /sys sampling, traffic counters
internal/diag         analysis, manual probe, path-MTU search, traceroute
internal/backup       backup, restore and one-time download links
web/embed.go          embeds web/dist into the binary
web/_app/             the React application
scripts/              installer, offline bundles and release build
```
