# Changelog

[中文](CHANGELOG.md) | **English**

Notable changes to `oixc-proxy` are recorded in this file. Versions follow [Semantic Versioning](https://semver.org/).

## [0.6.0] - 2026-10-06

### Added

- Make `traffic` query bounds and human-readable output respect the local timezone or `TZ`. Accept local timestamps without a suffix, `Z` and explicit UTC offsets; require an explicit offset for nonexistent/ambiguous DST times. Preserve Unix seconds in journals and JSON, with no history migration needed.
- Record local TCP/UDP application upload/download deltas and timestamps every minute in a synced mode-0600 JSONL journal beside the config/token file for `serve`/`serve-map`. A dedicated writer thread keeps disk I/O off the forwarding path, flushes on normal exit and retains history across restarts. Add `--traffic-file`, exclusive writer ownership, retry retained deltas after write failures and recover incomplete tails.
- Add `traffic [--all] [--from TIME] [--to TIME] [--json]` for read-only lifetime or sample-time range queries with TCP/UDP upload/download breakdowns. Reports include persisted samples only, not account billing; abnormal exits may lose unflushed traffic. Document precision, failure and storage boundaries in both READMEs.
- Match official v0.0.39 API identity with `User-Agent: oixCloud Helper` and `X-oixCloud-Client: oixcloud-helper`.
- Add `login --output PATH` to explicitly import the configured token through the official rebind API and save the Helper token in a new mode `0600` config. Other settings are preserved; the original config and running service are unchanged. Login never retries or uses fallback APIs, and startup/read-only commands never rebind automatically. Email/password login is not supported.

### Usage notes and verification

- SIGTERM, SIGINT (Ctrl-C) and normal exit write and sync a final partial-minute sample. Add real-process signal and TCP/UDP accounting regression tests. SIGKILL, crashes or power loss can still lose unflushed traffic.
- macOS updates explicitly send SIGTERM and wait for KeepAlive to relaunch the service. Align bilingual READMEs, deployment instructions and the deployment Skill on graceful restarts, default systemd signals and the generated unit's 10-second stop timeout.

## [0.5.0] - 2026-10-05

### Added

- `refresh-nodes` manually refreshes the running catalog through a private control socket without restarting. It waits for the actual result, retains the old catalog and pools on failure, and runs serially with scheduled and ECH-triggered refreshes.
- `reload-config` reloads the token, API URLs, filters, timeouts, concurrency, reuse settings, refresh interval and trace sampling. New state is validated and prepared before switching; failure retains the complete active configuration. Token or API URL changes first fetch and verify a fresh catalog. Established tunnels continue, and lower client connection limits count existing connections.
- `diagnose --output PATH` exports a sanitized mode-0600 JSON bundle and refuses to overwrite files. It includes the active configuration summary, process information, anonymous node status, the last 128 refresh/reload events and each node's last 16 ECH dial events. Tokens, PSKs, addresses, paths, node names, filter patterns and raw logs are excluded. Export still works with an invalid on-disk config.
- `/status` reports catalog refresh results, cache age, physical egress, TLS roots and ECH dial statistics. Per-node diagnostics include health, consecutive failures, DNS/TCP/TLS/total timings and p50/p95 over the last 64 successful physical connections. It does not probe nodes or count reused sessions again.
- `api-fallback-urls` configures up to three trusted HTTPS backup API endpoints. Network errors, timeouts and HTTP 5xx may fall back within one shared request budget; authentication, rate-limit, format and signature errors do not.
- `node-filter-lines`, `node-filter-regions`, `node-filter-include`, `node-filter-exclude` and `preview-nodes` provide local literal name filtering and read-only previews. Default Fusion/CIA filtering and existing bypasses remain available.
- Successful Clash provider responses include validated `Subscription-Userinfo` with actual traffic, quota and optional expiry. Metadata shares the account-bound catalog cache and is omitted when missing, invalid or stale; authentication failures clear it.

### Fixed

- The outer ECH ClientHello advertises browser ALPNs `h2` / `http/1.1`; the Snell protocol identifier remains inside the encrypted inner ClientHello.
- Rejected ECH configurations trigger a catalog refresh. Requests from multiple nodes coalesce with a 30-second cooldown, and refresh failures retain the existing catalog.
- DNS/TCP connection errors preserve underlying error types so common network failures can be classified correctly.

### Usage notes

- New management commands support only `serve` and use a mode-0600 Unix socket beside the configuration. Run as the service user (`sudo` for a root service).
- Changes to `listen`, `nodelist-listen`, `outbound-ip`, `udp-port-range` or `udp-advertise-address` require a restart and reject the entire reload.
- Unchanged nodes retain pools and metrics across refreshes and filter-only changes. Token or dial/reuse changes rebuild clients and retire old idle connections. Older account-bound caches remain readable; account metadata is populated after a successful refresh.
- Chinese and English command examples, troubleshooting, sanitization boundaries and installation version examples are updated.

## [0.4.0] - 2026-10-01

### Added

- `tcp-idle-timeout` closes TCP tunnels with no data moving in either direction. It defaults to 1 hour, accepts 1 minute through 24 hours, and applies to SOCKS5, HTTP CONNECT and plain HTTP forwarding.
- serve-map refreshes node routes in place every hour, so a node that rotates its address, PSK or ECH configuration no longer needs a restart. Ports stay bound to node names; added or removed nodes are only logged.

### Changed

- A plain HTTP proxy connection now forwards exactly one request, and the final response head always carries `Connection: close`. Later keep-alive requests can no longer reach the wrong upstream along with their `Proxy-Authorization`. Requests with ambiguous framing are rejected before dialing, `Expect: 100-continue` is supported, interim 1xx responses are passed through, and Upgrade requests are still relayed as an opaque tunnel.
- Listeners no longer stop on a per-connection accept error. Resource exhaustion (EMFILE, ENFILE, ENOBUFS, ENOMEM) is retried after a backoff, and any other unrecoverable error exits the process so the service manager can restart it.
- IPv6 source selection skips tentative and DAD-failed addresses and ranks global before ULA, preferred before deprecated, and stable before temporary. A non-loopback `outbound-ip` is still used as configured.

### Fixed

- Snell: flush after every record write, fixing relays that stalled with data buffered in TLS.
- Snell: probe idle connections before reuse; bound connection retirement to 2 seconds, and stop retiring idle connections one by one when a client closes.
- ECH: retry the handshake with retry configs provided by the server.
- SOCKS5: keep waiting for the response after the client half-closes instead of truncating it at the 2-second close timeout; an upstream that finishes first is a clean end, so its Snell connection returns to the pool.
- SOCKS5: a bad datagram is dropped instead of ending the whole UDP association; idle time counts traffic in both directions; a SOCKS5 failure reply is sent when the association cannot be set up.
- HTTP: forward bytes sent together with a CONNECT request; keep scanning headers for proxy credentials; dial IPv6 literals in absolute-form requests.
- DNS: ignore replies from the wrong source or for the wrong question, retry on SERVFAIL and truncated replies, and cache a lookup in full only when both A and AAAA succeeded; partial results are cached briefly.
- TLS: reload incomplete system trust stores in the background without blocking dials.
- Node catalog: unknown top-level keys are ignored, and unusable nodes are skipped and logged instead of rejecting the whole catalog.
- API: truncate error bodies on character boundaries, fixing a crash on multi-byte text such as Chinese.

### Performance

- Snell downloads are written straight from decrypted records, saving one copy.
- When an ECH connection attempt fails, the next address starts immediately (RFC 8305) instead of waiting for the 250ms stagger.
- On macOS, default-route lookups are reused and rechecked at most every 30 seconds, so dials no longer queue behind a `route` process.
- Trace fields are no longer built while tracing is off.

### Documentation

- IXP is no longer listed in the node filter description.

## [0.3.0] - 2026-10-01

### Performance

- Snell record AES-128-GCM now uses `ring`. Throughput is about 1.95–1.99× for 1 KiB records and about 2.8–2.94× for maximum-size records; 64-byte frames are slightly slower, and end-to-end throughput shows no stable measurable gain.

## [0.2.2] - 2026-09-29

### Fixed

- TLS: when an incomplete system trust store causes `UnknownIssuer`, refresh the store and retry once, with a 30-second cooldown between refreshes.

### Diagnostics

- Trace physical egress selection.

## [0.2.1] - 2026-09-15

### Fixed

- Keep the pinned `outbound-ip` when interface discovery (`getifaddrs`) is denied in restricted Linux environments; systemd units allow `AF_NETLINK`.

## [0.2.0] - 2026-09-15

### Added

- `udp-port-range` and `udp-advertise-address` pin the UDP relay port range and the advertised address.
- Bind to and track the physical egress: macOS binds the interface to bypass tunnel interfaces, a non-loopback `outbound-ip` is a strict source address, and network changes invalidate DNS caches, address preference and idle connections.
- The API User-Agent is derived from the Cargo package version.

### Fixed

- The node catalog cache is bound to the account (HMAC fingerprint and a versioned envelope); legacy, oversized and other accounts' caches are rejected.

### Documentation

- Chinese and English READMEs and deployment skill docs, plus notes on UDP defaults.

## [0.1.0] - 2026-09-01

First Rust release.

### Added

- A mixed HTTP/SOCKS5 inbound listener; `socks5-listen` is renamed to `listen`, with the old name kept as an alias.
- The node filter publishes only nodes whose names contain `Fusion` or a standalone `CIA` token; `--disable-node-filter` or `?all=1` turns it off.
- Node lists advertise HTTP proxies by default and SOCKS5 with `socks=1`; a Clash provider at `/clash-proxies.yaml`; the Surge provider no longer includes test-timeout.
- Start from the node cache.
- A `version` subcommand that prints the version, commit and build time.
- Raise `RLIMIT_NOFILE` at startup.
- A release pipeline for macOS and Linux musl (x86_64/aarch64) with `install.sh`, and the `DEPLOY.md` deployment guide.

### Performance

- Snell hot path: in-place AES-GCM, buffered reads and batched writes, ARMv8 crypto instructions, and no async mutexes.
- DNS and TCP racing: a shared transport context, coalesced signed DNS queries, concurrent A/AAAA lookups and staggered connection attempts.
- Dial time budgets, sampled performance tracing and connection reuse tuning.

[0.6.0]: https://github.com/we11adam/oixc-proxy/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/we11adam/oixc-proxy/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/we11adam/oixc-proxy/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/we11adam/oixc-proxy/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/we11adam/oixc-proxy/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/we11adam/oixc-proxy/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/we11adam/oixc-proxy/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/we11adam/oixc-proxy/releases/tag/v0.1.0
