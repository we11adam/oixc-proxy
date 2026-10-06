# oixc-proxy

[中文](README.md) | **English**

`oixc-proxy` is a clean-room Rust client and local named-node proxy for
oixCloud. It fetches, authenticates and decrypts the managed node catalog, then
publishes only nodes whose names contain `Fusion` or a standalone `CIA`
marker through one mixed HTTP/SOCKS5 listener and a separate HTTP nodelist
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
sh install.sh --version v0.5.0
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

Use $oixc-proxy-deploy to update root@router.lan to v0.5.0. Preserve its
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
only available on the SOCKS path). Loopback listeners advertise each node's
UDP capability directly. A remote listener advertises UDP only when a fixed
relay port range and a client-reachable address are both configured, avoiding
providers that claim unusable UDP support. The username is a reversible URL-safe
encoding of the exact managed node name; the password is a stable HMAC-derived
routing secret. HTTP clients send those as `Proxy-Authorization: Basic`. The
access token, node address, PSK and ECH configuration are never returned by
the nodelist HTTP endpoint.

Only names containing `Fusion` or a standalone `CIA` token,
case-insensitively, are published by default. Treating the acronym as a token
avoids admitting ordinary names such as `Special`. An empty filtered catalog
is rejected so a control-plane naming change cannot expose ordinary nodes.
`GET` `/surge-proxies.conf?all=1` and `/clash-proxies.yaml?all=1` publish the
full catalog; those extra nodes are still routed through the same mixed
listener. Append `socks=1` when the client should use SOCKS5.

## Service configuration

`serve`, `login`, `information`, `install-launch-agent` and `install-systemd` read
`~/.config/oixc-proxy/oixc-proxy.conf` by default. `--config PATH` selects a
different file.

### Log in as oixCloud Helper

API requests match official v0.0.39 with `User-Agent: oixCloud Helper` and
`X-oixCloud-Client: oixcloud-helper`. Headers alone do not migrate an existing
token's client ownership. To import your configured token:

```sh
oixc-proxy login --output "$HOME/.config/oixc-proxy/oixc-proxy.helper.conf"
```

`login` sends one bodyless `POST /api/v1/token/rebind` to the primary API with
the existing bearer token. It saves the returned Helper token in a new mode
`0600` config while preserving other settings. The destination must not exist.
It never retries, uses fallback APIs or prints the token. This changes server-side
token ownership; a failed request or timeout may still have issued a token.

After success, copy the new token into your original config and run
`oixc-proxy reload-config` as the service user. Login does not modify the running
service. Reload fetches and verifies a fresh catalog and rejects caches bound to
the old token. This aligns the existing token-import workflow; email/password
login is not supported. Service startup and read-only commands never rebind
tokens automatically. See the [official-client analysis](docs/2026-10-06_reverse-oixcloud-helper-login-report.md).

### Configuration format

The format is strict `key=value`. Blank lines and `#` comments are accepted;
unknown keys, duplicate keys, empty values, quoting and sections are rejected.
The file must be a regular file with Unix mode `0600` or stricter.

| Key | Required | Default | Meaning |
| --- | --- | --- | --- |
| `token` | Yes | — | oixCloud access token |
| `api-base-url` | No | `https://oix-api.dler.io` | Primary control-plane API |
| `api-fallback-urls` | No | Unset | Comma-separated trusted HTTPS API URLs, at most three |
| `listen` | No | `127.0.0.1:6172` | Mixed HTTP/SOCKS5 numeric IP and port |
| `nodelist-listen` | No | `127.0.0.1:6173` | HTTP numeric IP and port |
| `outbound-ip` | Conditional | SOCKS5 bind IP | Provider/UDP address; a non-loopback value also pins control-plane and node connections to that physical source IP |
| `udp-port-range` | Conditional | Unset (OS-assigned port) | Fixed SOCKS5 UDP relay range as `START-END`, limited to 4096 ports |
| `udp-advertise-address` | Conditional | Unset (bound IP) | Client-reachable address returned by SOCKS5 UDP ASSOCIATE |
| `node-refresh-interval` | No | `1h` | Catalog refresh period, `1m` through `24h` |
| `request-timeout` | No | `15s` | Control-plane and node operation deadline, up to `2m` |
| `tcp-idle-timeout` | No | `1h` | Close a TCP tunnel after no data moves in either direction, `1m` through `24h` |
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
udp-port-range=10000-10099
udp-advertise-address=10.0.0.16
node-refresh-interval=1h
```

Neither `udp-port-range` nor `udp-advertise-address` has a static default. They
must be configured together or both omitted; setting only one prevents startup.
When both are omitted, each UDP association uses an OS-assigned port and reports
the actual bound IP. This suits the default loopback listener; a remote listener
does not advertise UDP capability in provider output in this mode. When the pair
is configured, the server rotates through the fixed range, skips occupied ports,
and lets the operating system release ports for reuse when associations end.
Docker and NAT deployments must map the same UDP port numbers and allow the
range through the firewall.

With the default loopback setup, control-plane, private DNS, and ECH-TLS node
connections automatically use an active non-virtual physical interface. On
macOS the socket is interface-bound so traffic does not loop back into a Surge
Enhanced Mode tunnel. A non-loopback `outbound-ip` is a strict source-address
pin: if it disappears from the active interfaces, connections fail explicitly
instead of silently using another path. The route is checked on demand every two
seconds. An interface or address change invalidates private DNS results, the
last-success address preference, and idle reusable Snell transports so new
connections recover on the new network.

Startup loads `nodes-cache.yaml` beside the config file when present, so the
SOCKS5 and nodelist listeners can bind before the control-plane fetch
finishes. The cache is mode `0600`, holds the last validated catalog, and is
bound to the current token through a one-way account fingerprint. A token
change rejects the old cache. A later refresh failure keeps the current
account's previous catalog. The first start still requires a successful fetch
if no usable cache exists. Unchanged node profiles
retain their Snell clients and idle connection pools; changed, added and
removed profiles are rotated atomically.

## Commands

### Query local traffic

`serve` and `serve-map` automatically record TCP/UDP application upload/download
bytes forwarded through Snell. These are local counters, not oixCloud billing:
Snell/TLS handshakes, encryption, padding, provider requests and API calls are
excluded. Downloads count when read from upstream, even if delivery to the local
client subsequently fails. Uploads count completed successful writes; failed or
cancelled partial writes can be undercounted.

```sh
# All retained history, including previous service runs
oixc-proxy traffic --all
# UTC range; either endpoint can also be omitted
oixc-proxy traffic --from 2026-10-06T00:00Z --to 2026-10-07T00:00Z
# Default journal beside a custom config, or an explicit journal with JSON output
oixc-proxy traffic --config /path/to/oixc-proxy.conf --json
oixc-proxy traffic --file /path/to/traffic.jsonl --all --json
```

The default journal is `traffic.jsonl` beside the service config, or beside the
token file for `serve-map`. A dedicated thread normally samples at each UTC
minute boundary, appends one JSON line and syncs it to disk. Forwarding performs
no file I/O. SIGTERM, Ctrl-C or normal return flushes a final partial-minute
sample. The journal and writer lock have mode `0600`; no accounts, nodes,
destinations or credentials are recorded. Query as the service user (`sudo` for
root-owned services).

Times accept Unix seconds or UTC `YYYY-MM-DDTHH:MM[:SS]Z`, never implicit local
time. Ranges are `[from, to)` and select entire records by their **sample timestamp**,
not individual packet timestamps, with normally one-minute precision. Queries
read persisted history only, make no API requests, and exclude the current
unflushed interval. Traffic before enabling recording cannot be recovered.
Lifetime means all retained history in this file, across restarts, refreshes and
token changes; it is not account-wide lifetime usage.

Crashes, forced kills or power loss can lose the unflushed interval, normally up
to roughly one minute. Disk-write failures retain in-memory deltas for the next
successful append, reported as `extended_windows`; exiting after prolonged
failures can lose more. Queries ignore an incomplete final line and startup
repairs it when the format is recognizable. If the first record is too truncated
to identify, startup refuses to avoid truncating an unrelated file.
Corrupt complete records cause errors rather than being silently
skipped. History is append-only, with no automatic rotation or pruning, using
roughly 100 MB/year continuously. Deleting it loses history; include it in backups.

Separate instances must use separate journals; only one writer can own a file:

```sh
oixc-proxy serve --config /path/to/oixc-proxy.conf --traffic-file /path/to/traffic.jsonl
oixc-proxy serve-map --token-file /path/to/token.txt --traffic-file /path/to/map-traffic.jsonl
```

The parent directory must exist and be writable. Existing files must be private
regular journals owned by the service user; symlinks and broad permissions are
rejected. Use the matching `traffic --file` when overriding the default location.
The path is a startup option and cannot be hot-reloaded.

### Management and diagnostics

Run `oixc-proxy refresh-nodes [--config PATH]` to refresh the running `serve`
instance manually. Configuration changes can be applied with
`oixc-proxy reload-config [--config PATH]`. Reload supports the token, API URLs,
filters, timeouts, connection/dial limits, reuse settings, refresh interval and
trace sampling. A token or API URL change must fetch and verify a fresh catalog;
validation or preparation failure retains the complete active configuration.
Filter-only changes retain unchanged clients and metrics. Token or dial/reuse
changes rebuild clients and retire old idle connections; established tunnels
continue with their original options. Lower connection limits count existing
connections and wait for them to finish before admitting more.

Changes to `listen`, `nodelist-listen`, `outbound-ip`, `udp-port-range` or
`udp-advertise-address` require a restart and reject the entire reload. Both
commands use the private control socket and only support `serve`.

Export a sanitized bundle while preserving the running process:

```sh
oixc-proxy diagnose --output diagnostics.json
sudo oixc-proxy diagnose --config /path/to/oixc-proxy.conf --output diagnostics.json
```

The JSON file is created with mode `0600` and must not exist. It contains running
build/version/PID information, service start time, the active configuration
summary, catalog/TLS-root/anonymous node status, the last 128 refresh/reload events
and each node's last 16 ECH dial events. Events contain only timestamps, fixed
types, error categories and failure stages; `error: null` means success.
Raw logs/config files, tokens, PSKs, API/upstream/destination addresses, local IPs,
interface names, paths, node names and filter patterns are excluded. `node-1` IDs
are local to the bundle and may change between exports. Export still works when
the on-disk config is invalid and reports the configuration actually in use.
It does not restart, probe or refresh; it waits behind any ongoing serialized
management operation. Only `serve` supports this command.

Manual refresh updates the running `serve`
instance without restarting. The command uses a private mode-0600 Unix socket
beside the config; run it as the service user (`sudo` for a root service).
It waits for the actual result and exits 1 on failure, retaining the active catalog
and pools. Manual, scheduled and ECH-triggered refreshes run serially. It uses
the service's active token, not a changed on-disk token. `serve-map` does not
provide this control interface.

Successful Clash provider GET/HEAD responses include validated `Subscription-Userinfo`
with actual upload/download/total and optional expiry values. Metadata shares the
account-bound catalog cache. Missing, malformed, over-24-hour or invalidly timestamped
metadata is omitted, never filled with zeroes. Refreshes update metadata even when
nodes are unchanged; authentication/forbidden errors clear it in memory. Legacy
caches remain readable but have no metadata until refreshed. Provider bodies are
unchanged and Surge responses do not include this header.

Configure any of `node-filter-lines`, `node-filter-regions`, `node-filter-include`
or `node-filter-exclude` to replace the default Fusion/CIA selection. Alternatives
within each field use `|` (OR); fields combine with AND and exclusions take priority.
Line filters match independent ASCII markers such as `Fusion|CIA|IXP`. Region and
name filters match case-insensitive literal substrings, because the catalog lacks
structured region metadata. No regex is evaluated. Each field allows at most 64
nonempty alternatives and 4096 bytes. JSON uses `nodeFilterLines`, `nodeFilterRegions`,
`nodeFilterInclude` and `nodeFilterExclude`; `serve-map` accepts corresponding flags.

Run `oixc-proxy preview-nodes` to inspect selected names/counts from the current
account cache (fetching if unavailable), or append `--refresh` to fetch explicitly.
Preview does not write caches, change the service or update panel settings, and
can show zero matches. The service rejects an empty selection. Remove all four
settings to restore defaults. `--disable-node-filter` / provider `?all=1` bypass
local selection but cannot restore nodes omitted by the API.

API fallback applies only to network errors, timeouts and HTTP 5xx. All attempts
and response reads share `request-timeout`, reserving time for remaining URLs.
401/403/407/429, malformed responses and signature failures do not trigger retry.
HTTPS verification, signatures, direct physical egress and no-redirect policy
remain enabled. No fallback is assumed by default; configure only trusted API
URLs for the same service, because they receive your token. JSON configuration
uses `apiBaseURL` and `apiFallbackURLs`.

Use `curl -fsS http://127.0.0.1:6173/status` to diagnose faults without restarting.
`GET`/`HEAD /status` reports catalog refresh timestamps/errors, cache age, physical
egress, TLS root count/generation/load completeness and cumulative ECH dial results.
Timestamps are Unix seconds; counters reset on process restart. `ready` means a
catalog is loaded. `/healthz` only indicates HTTP liveness; neither endpoint probes
upstream nodes. HTTP 401/403/407/429 have distinct sanitized error categories,
and valid `Retry-After` seconds appear in rate-limit errors. Status omits tokens,
PSKs, node addresses and remote error bodies. Expose it only to trusted networks.

`nodes` reports per-node ECH health (`unobserved`, `healthy`, `degraded`), consecutive
failures, last DNS/TCP/TLS/total timings in milliseconds, last failure stage, and
p50/p95 over the last 64 successful physical connections. Retries accumulate stage
time; timeouts retain partial timings. Reused sessions do not create samples.
`healthy` describes the latest ECH connection, not reachability of every destination.
Unchanged nodes retain statistics across refreshes; changed connection parameters
or process restarts reset them.

```text
oixc-proxy traffic [--config PATH | --file PATH] [--all] [--from TIME] [--to TIME] [--json]
oixc-proxy login [--config PATH] --output PATH
oixc-proxy information [--config PATH] --output PATH

oixc-proxy serve [--config PATH] [--traffic-file PATH]
oixc-proxy serve-map [--token-file PATH] [--listen IP] [--base-port PORT] [--traffic-file PATH]
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

`serve-map` fetches the same Fusion/CIA catalog itself, then gives each
node one loopback SOCKS5 port beginning at 7200 by default. Its default
protected token file is `token.txt`. It does not provide the HTTP nodelist
endpoint. The catalog is refreshed hourly: a node whose address, PSK or ECH
configuration changed is updated on its existing port, while added or removed
nodes are only logged, because renumbering ports would send clients to other
nodes; restart `serve-map` to remap them.

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
6. Fails closed to the Fusion/CIA name allowlist.

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

After building release, verify features with an isolated process and temporary
ports/config/cache, without changing an existing service:

```sh
OIXC_LIVE_CONFIG="$HOME/.config/oixc-proxy/oixc-proxy.conf" \
OIXC_LIVE_BINARY="$PWD/target/release/oixc-proxy" \
cargo test --test live_features -- --ignored
```

This opt-in test makes read-only API requests using the configured token,
checks status, filter preview, Clash GET/HEAD metadata and a real HTTPS proxy
request, then stops its temporary service process.

The ECH outer ClientHello advertises `h2` / `http/1.1`; the real `snell-ech/1`
ALPN is confined to the encrypted inner hello. A small [rustls patch](vendor/README.md)
provides separate ALPN settings while retaining certificate verification and mandatory ECH.

An ECH rejection wakes the catalog refresh loop in both `serve` and `serve-map`.
Concurrent failures are coalesced with a 30-second cooldown. Failed refreshes
retain the previous catalog. Authenticated server retry configs still allow one
handshake retry; refreshed nodes serve subsequent connections without replaying payloads.

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release
```

Unit tests include fixed Go/Rust compatibility vectors for request HMAC,
Identity v2, Argon2id record keys, CONNECT encoding and private DNS signatures.
Live validation should additionally cover `/healthz`, a non-empty
Fusion/CIA provider, shared-port SOCKS routing, `serve-map` and a real
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
