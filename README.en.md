# oixc-proxy

[中文](README.md) | **English**

`oixc-proxy` is a clean-room Rust client and local named-node proxy for
oixCloud. It fetches, authenticates and decrypts the managed node catalog, then
publishes only nodes whose names contain `Fusion` or standalone `CIA`/`IXP`
markers through one mixed HTTP/SOCKS5 listener and a separate HTTP nodelist
listener.

This repository is the Rust rewrite of the Go implementation in `oixc`. The
binary name, commands, configuration, HTTP endpoints, Surge provider format,
SOCKS5 routing credentials, control-plane authentication and Snell/ECH wire
behavior are intentionally compatible.

## Install a release

GitHub Releases provide native macOS binaries and static musl Linux binaries
for x86-64 and aarch64. With an authenticated GitHub CLI, download and inspect
the installer, then run it:

```sh
gh release download --repo we11adam/oixc-proxy --pattern install.sh --clobber
sh install.sh
```

For a public repository, the installer can instead be downloaded from
`https://github.com/we11adam/oixc-proxy/releases/latest/download/install.sh`.
Private repository assets require `gh`, authenticated by its existing login or
a read-only `GH_TOKEN`/`GITHUB_TOKEN`.

The installer detects the host target, verifies the archive against the
release `SHA256SUMS`, checks the binary version and atomically installs
`/usr/local/bin/oixc-proxy`. Install a fixed version or a user-writable path
with:

```sh
sh install.sh --version v0.1.0
sh install.sh --install-dir "$HOME/.local/bin"
```

It installs only the binary; it does not create a config, install a service or
restart an existing process. Continue with the platform service instructions
below or the complete [deployment guide](DEPLOY.md).

## Use the deployment Skill with an agent

This repository includes an agent-facing
[`oixc-proxy-deploy` Skill](.agents/skills/oixc-proxy-deploy/SKILL.md). Agents
such as Codex that support repository-local Skills can discover it when opened
in this repository. You can also invoke it explicitly with
`$oixc-proxy-deploy` in the prompt.

Example prompts:

```text
Use $oixc-proxy-deploy to install the latest Release locally, then verify the
version and health status.

Use $oixc-proxy-deploy to update root@router.lan to v0.1.0. Preserve its
existing config and service mechanism; verify the new PID, listeners, /healthz,
and provider endpoint, and roll back on failure.

Use $oixc-proxy-deploy to publish the current Cargo.toml version, follow the
GitHub Release workflow, and download and verify every release asset.
```

Name every authorized target host and desired version in the prompt, and state
whether the agent may create or change configuration and services. Do not put
tokens directly in prompts. Private Releases should use an existing `gh` login
or a securely injected read-only token in the agent environment. The Skill
operates only on this Rust repository and preserves existing configuration and
service management during updates. See the [deployment guide](DEPLOY.md) for
platform details.

## Build

Rust 1.85 or newer is required.

```sh
cargo test
cargo build --release
```

The optimized binary is `target/release/oixc-proxy`. Release builds use
`opt-level=3`, fat LTO, one codegen unit, symbol stripping and abort-on-panic.
On aarch64 macOS and Linux, the repository build configuration enables the
RustCrypto ARMv8 AES and PMULL backends. Those backends still detect CPU
support at runtime and safely fall back when the extensions are unavailable.

## Publish a release

Set the package version in `Cargo.toml`, commit the release, then push a matching
`vVERSION` tag. For example, package version `0.1.0` requires tag `v0.1.0`.
The release workflow rejects mismatches, builds all four supported targets,
generates `SHA256SUMS` and creates or updates the GitHub Release.

## Configure and run

Create the protected service configuration:

```sh
install -d -m 0700 ~/.config/oixc-proxy
cp oixc-proxy.conf.example ~/.config/oixc-proxy/oixc-proxy.conf
chmod 0600 ~/.config/oixc-proxy/oixc-proxy.conf
```

Replace the example token, then start the foreground service:

```sh
target/release/oixc-proxy serve
```

The default endpoints are:

| Endpoint | Address | Purpose |
| --- | --- | --- |
| Mixed proxy | `127.0.0.1:6172` | HTTP and SOCKS5 on one port; routes provider credentials to one named node |
| Nodelist | `http://127.0.0.1:6173/surge-proxies.conf` | Surge list (`?all=1` every node, `?socks=1` advertise SOCKS5) |
| Clash | `http://127.0.0.1:6173/clash-proxies.yaml` | Clash list (`?all=1` every node, `?socks=1` advertise SOCKS5) |
| Health | `http://127.0.0.1:6173/healthz` | Readiness probe |

Example Surge group:

```ini
[Proxy Group]
OIXC = select, policy-path=http://127.0.0.1:6173/surge-proxies.conf, update-interval=3600
```

Every provider entry points to the shared mixed listener. Entries are HTTP
proxies by default; `?socks=1` advertises SOCKS5 instead (UDP ASSOCIATE is
only available on the SOCKS path). The username is a reversible URL-safe
encoding of the exact managed node name; the password is a stable HMAC-derived
routing secret. HTTP clients send those as `Proxy-Authorization: Basic`. The
access token, node address, PSK and ECH configuration are never returned by
the nodelist HTTP endpoint.

Only names containing `Fusion` or standalone `CIA`/`IXP` tokens,
case-insensitively, are published by default. Treating the acronyms as tokens
avoids admitting ordinary names such as `Special`. An empty filtered catalog
is rejected so a control-plane naming change cannot expose ordinary nodes.
`GET` `/surge-proxies.conf?all=1` and `/clash-proxies.yaml?all=1` publish the
full catalog; those extra nodes are still routed through the same mixed
listener. Append `socks=1` when the client should use SOCKS5.

## Service configuration

`serve`, `information`, `install-launch-agent` and `install-systemd` read
`~/.config/oixc-proxy/oixc-proxy.conf` by default. `--config PATH` selects a
different file.

The format is strict `key=value`. Blank lines and `#` comments are accepted;
unknown keys, duplicate keys, empty values, quoting and sections are rejected.
The file must be a regular file with Unix mode `0600` or stricter.

| Key | Required | Default | Meaning |
| --- | --- | --- | --- |
| `token` | Yes | — | oixCloud access token |
| `listen` | No | `127.0.0.1:6172` | Mixed HTTP/SOCKS5 numeric IP and port |
| `nodelist-listen` | No | `127.0.0.1:6173` | HTTP numeric IP and port |
| `outbound-ip` | Conditional | SOCKS5 bind IP | Specific IP placed in provider entries and used for UDP binding |
| `node-refresh-interval` | No | `1h` | Catalog refresh period, `1m` through `24h` |
| `request-timeout` | No | `15s` | Control-plane and node operation deadline, up to `2m` |
| `udp-idle-timeout` | No | `5m` | Idle lifetime of one SOCKS5 UDP association |
| `max-client-connections` | No | `256` | Process-wide mixed proxy connection limit, `1` through `4096` |
| `dial-concurrency` | No | `32` | Process-wide fresh ECH-TLS dial limit, `1` through `1024` |
| `per-node-dial-concurrency` | No | `8` | Fresh ECH-TLS dial limit for one node, `1` through `128` |
| `reuse-max-idle` | No | `8` | Maximum idle reusable transports retained per node |
| `reuse-max-uses` | No | `32` | Logical sessions allowed on one physical transport |
| `reuse-idle-timeout` | No | `90s` | Maximum idle age of a reusable transport |
| `perf-trace-sample-every` | No | `0` | Emit detailed trace for one in every N requests; `0` disables tracing |

Both listeners may use `0.0.0.0` or `[::]`. A wildcard `listen` address requires
a specific, same-family `outbound-ip`. For a trusted LAN host:

```ini
token=REPLACE_WITH_OIXC_ACCESS_TOKEN
listen=0.0.0.0:6172
nodelist-listen=0.0.0.0:6173
outbound-ip=10.0.0.16
node-refresh-interval=1h
```

Startup loads `nodes-cache.yaml` beside the config file when present, so the
SOCKS5 and nodelist listeners can bind before the control-plane fetch
finishes. The cache is mode `0600` and holds the last validated catalog. A
later refresh failure keeps the previous catalog. The first start still
requires a successful fetch if no cache exists. Unchanged node profiles
retain their Snell clients and idle connection pools; changed, added and
removed profiles are rotated atomically.

## Commands

```text
oixc-proxy information [--config PATH] --output PATH

oixc-proxy serve [--config PATH]
oixc-proxy serve-map [--token-file PATH] [--listen IP] [--base-port PORT]
oixc-proxy version
oixc-proxy install-launch-agent [--config PATH]
oixc-proxy install-systemd [--config PATH]
```

`information` performs the read-only account/API request and creates a new JSON
file with mode `0600`. It refuses to replace an existing file.

`serve` is the normal named-node gateway. Username/password pairs from the
generated provider select different managed nodes on one mixed HTTP/SOCKS5
port. It also serves `GET`/`HEAD` for `/surge-proxies.conf`,
`/clash-proxies.yaml` and `/healthz`. Append `?all=1` to list every node, or
`?socks=1` to advertise SOCKS5 instead of HTTP.

`serve-map` fetches the same Fusion/CIA/IXP catalog itself, then gives each
node one loopback SOCKS5 port beginning at 7200 by default. Its default
protected token file is `token.txt`. It does not provide the HTTP nodelist
endpoint.

`version` prints the package version, the git commit id the binary was built
from (short hash, suffixed `-dirty` when the working tree had uncommitted
changes) and the UTC build timestamp. The metadata is captured at compile time
by `build.rs`; outside a git checkout the commit id is reported as
`unknown`.

The removed `serve-provider`, single-node `serve --index`, `dump-*`, `probe-*`,
`seal-bundle`, `install-bundle` and `inspect-binary` commands remain removed.
The reverse-engineered knowledge they depended on is retained in
[docs/protocol.md](docs/protocol.md).

## Install on macOS

Run as the logged-in user:

```sh
target/release/oixc-proxy install-launch-agent
```

The command validates the config, installs the current executable at
`/usr/local/bin/oixc-proxy`, creates
`~/Library/LaunchAgents/io.oixc.proxy.plist`, bootstraps it and starts it. If
the binary copy needs administrator privileges, the installer requests `sudo`
for that copy only. Running the entire installer with `sudo` is rejected.

Logs:

```text
~/Library/Logs/oixc-proxy.stdout.log
~/Library/Logs/oixc-proxy.stderr.log
```

Inspect the service:

```sh
launchctl print "gui/$(id -u)/io.oixc.proxy"
```

When `perf-trace-sample-every` is nonzero, the stderr log contains sanitized,
request-scoped performance events for SOCKS parsing, DNS/TCP/TLS setup, the
initial Snell flight, first data in both directions and relay cleanup. Tracing
is disabled by default so synchronous log output cannot slow the data plane.
It never logs tokens, PSKs, target names, ECH configuration or derived key
material.

## Install on Linux

Run as the login user:

```sh
target/release/oixc-proxy install-systemd
```

The command installs the same `/usr/local/bin/oixc-proxy`, creates
`~/.config/systemd/user/oixc-proxy.service`, reloads the user manager and
enables the service. It refuses to overwrite an existing unit.

```sh
systemctl --user status oixc-proxy.service
journalctl --user -u oixc-proxy.service
```

On a headless machine, an administrator can preserve the user service after
logout with `loginctl enable-linger USER`.

## Architecture and security properties

The control plane:

1. Generates a fresh age/X25519 identity for every managed request.
2. Sends the bearer token, Unix timestamp, age recipient and request HMAC.
3. Verifies the HMAC over the exact encrypted response string.
4. Strictly decodes Base64, ASCII armor and age, with 8 MiB limits.
5. Strictly parses one YAML document and validates the Snell ECH profile.
6. Fails closed to the Fusion/CIA/IXP name allowlist.

The data plane:

```text
Surge / Clash provider
  -> shared mixed HTTP/SOCKS5 listener
  -> username selects a managed node
  -> signed private DNS for cloud-nodes.com
  -> certificate-verified TLS 1.3 with mandatory ECH
  -> TLS exporter-bound Snell Identity v2
  -> Snell v4 TCP or UDP records
  -> requested destination
```

Connections are lazy: catalog loading does not probe all nodes. For a new TCP
session, Identity v2 and the encrypted CONNECT record are encoded into one TLS
write. The SOCKS success reply does not wait for the Snell CONNECT status, so
the client can send its first payload immediately; the status is consumed by
the first upstream read. Reusable transports are returned to the pool only
after both peers exchange the Snell zero record.

All node dialers share one system root store, crypto provider and signed-DNS
cache. Cold signed-DNS A/AAAA lookups run concurrently and coalesce by host;
TCP address attempts use a staggered Happy Eyeballs race and remember the last
successful address for the node.

The cryptographic and protocol layers are implemented in this repository.
Rust crates provide primitives (`argon2`, `aes-gcm`, `hmac`, `sha2`), age and
ECH-TLS (`rustls`); no third-party Snell implementation is used.

## Development checks

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release
```

Unit tests include fixed Go/Rust compatibility vectors for request HMAC,
Identity v2, Argon2id record keys, CONNECT encoding and private DNS signatures.
Live validation should additionally cover `/healthz`, a non-empty
Fusion/CIA/IXP provider, shared-port SOCKS routing, `serve-map` and a real
HTTPS request.

## Go/Rust Snell client benchmark

The repository contains a loopback-only Rust benchmark server and matching
Go/Rust clients. The server validates the real Identity v2 handshake, decodes
Snell v4 records, implements the zero-record reuse handshake, and echoes
application payloads. Both clients exercise their production Snell client and
pool implementations.

Run the standard comparison matrix:

```sh
scripts/benchmark-go-vs-rust.sh
```

The script builds optimized clients, starts the server on
`127.0.0.1:19090`, and compares fresh connections, sequential reuse, parallel
reuse, a production-like 1 MiB stream split into 32 KiB application writes,
and a single-write 1 MiB API stress workload. Worker response buffers are
reused so allocator noise is not charged to each operation. Set
`GO_OIXC_ROOT` if the Go repository is not at `/Users/adam/Projects/oixc-go`,
`BENCH_LISTEN` to select another loopback port, or `RESULTS_FILE` to retain the
raw NDJSON results.

This benchmark deliberately replaces ECH-TLS with loopback TCP and one static
exporter value. It isolates Identity v2, Argon2id, Snell v4 framing/encryption,
application I/O, and connection pooling. It does not measure DNS, TCP network
RTT, TLS/ECH handshakes, SOCKS5 parsing, or remote-node performance.

Run the Rust-only end-to-end loopback gateway matrix separately:

```sh
scripts/benchmark-rust-gateway.sh
```

It adds a new local TCP connection, SOCKS5 negotiation, the fixed-route
gateway, relay tasks and optional performance tracing around every logical
operation while retaining the authenticated Snell benchmark server. Set
`TRACE_SAMPLE_EVERY=1` to quantify full trace overhead, or leave it unset to
measure the default no-trace data path.
