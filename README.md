# oixc-proxy

`oixc-proxy` is a clean-room Rust client and local named-node proxy for
oixCloud. It fetches, authenticates and decrypts the managed node catalog, then
publishes only premium/love Fusion nodes through one SOCKS5 listener and a
separate HTTP nodelist listener.

This repository is the Rust rewrite of the Go implementation in `oixc`. The
binary name, commands, configuration, HTTP endpoints, Surge provider format,
SOCKS5 routing credentials, control-plane authentication and Snell/ECH wire
behavior are intentionally compatible.

## Build

Rust 1.85 or newer is required.

```sh
cargo test
cargo build --release
```

The optimized binary is `target/release/oixc-proxy`. Release builds use
`opt-level=3`, fat LTO, one codegen unit, symbol stripping and abort-on-panic.

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
| SOCKS5 | `127.0.0.1:6172` | Routes provider credentials to one named node |
| Nodelist | `http://127.0.0.1:6173/surge-proxies.conf` | Surge external-policy list |
| Health | `http://127.0.0.1:6173/healthz` | Readiness probe |

Example Surge group:

```ini
[Proxy Group]
OIXC = select, policy-path=http://127.0.0.1:6173/surge-proxies.conf, update-interval=3600
```

Every provider entry points to the shared SOCKS5 listener. The username is a
reversible URL-safe encoding of the exact managed node name; the password is a
stable HMAC-derived routing secret. The access token, node address, PSK and ECH
configuration are never returned by the HTTP endpoint.

Only names containing `Fusion`, case-insensitively, are published. An empty
filtered catalog is rejected so a control-plane naming change cannot
accidentally expose ordinary nodes.

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
| `socks5-listen` | No | `127.0.0.1:6172` | SOCKS5 numeric IP and port |
| `nodelist-listen` | No | `127.0.0.1:6173` | HTTP numeric IP and port |
| `outbound-ip` | Conditional | SOCKS5 bind IP | Specific IP placed in provider entries and used for UDP binding |
| `node-refresh-interval` | No | `1h` | Catalog refresh period, `1m` through `24h` |

Both listeners may use `0.0.0.0` or `[::]`. A wildcard SOCKS5 listener requires
a specific, same-family `outbound-ip`. For a trusted LAN host:

```ini
token=REPLACE_WITH_OIXC_ACCESS_TOKEN
socks5-listen=0.0.0.0:6172
nodelist-listen=0.0.0.0:6173
outbound-ip=10.0.0.16
node-refresh-interval=1h
```

The initial catalog fetch must succeed. A later refresh failure keeps the
previous catalog. Unchanged node profiles retain their Snell clients and idle
connection pools; changed, added and removed profiles are rotated atomically.

## Commands

```text
oixc-proxy information [--config PATH] --output PATH
oixc-proxy serve [--config PATH]
oixc-proxy serve-map [--token-file PATH] [--listen IP] [--base-port PORT]
oixc-proxy install-launch-agent [--config PATH]
oixc-proxy install-systemd [--config PATH]
```

`information` performs the read-only account/API request and creates a new JSON
file with mode `0600`. It refuses to replace an existing file.

`serve` is the normal named-node gateway. SOCKS username/password pairs from
the generated provider select different managed nodes on one port. It also
serves `GET`/`HEAD` for `/surge-proxies.conf` and `/healthz`.

`serve-map` fetches the same Fusion catalog itself, then gives each node one
loopback SOCKS5 port beginning at 7200 by default. Its default protected token
file is `token.txt`. It does not provide the HTTP nodelist endpoint.

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

The stderr log contains sanitized, request-scoped performance events for SOCKS
parsing, DNS/TCP/TLS setup, the initial Snell flight, first data in both
directions and relay cleanup. It never logs tokens, PSKs, target names, ECH
configuration or derived key material.

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
6. Fails closed to the Fusion-only catalog.

The data plane:

```text
Surge provider
  -> shared SOCKS5 listener
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
Live validation should additionally cover `/healthz`, the 74-entry Fusion
provider, shared-port SOCKS routing, `serve-map` and a real HTTPS request.

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
reuse, and 1 MiB transfer workloads. Set `GO_OIXC_ROOT` if the Go repository is
not at `/Users/adam/Projects/oixc`, `BENCH_LISTEN` to select another loopback
port, or `RESULTS_FILE` to retain the raw NDJSON results.

This benchmark deliberately replaces ECH-TLS with loopback TCP and one static
exporter value. It isolates Identity v2, Argon2id, Snell v4 framing/encryption,
application I/O, and connection pooling. It does not measure DNS, TCP network
RTT, TLS/ECH handshakes, SOCKS5 parsing, or remote-node performance.
