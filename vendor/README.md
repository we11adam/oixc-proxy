# rustls ECH cover ALPN patch

`rustls/` is crates.io rustls (version in `rustls/Cargo.toml`, licenses retained)
with `rustls-ech-outer-alpn.patch` applied; packaging metadata, benches and
examples are omitted. The application needs separate ALPN values in the encrypted
inner ClientHello and the public outer ClientHello. Upstream, up to 0.23.45 and
0.24.0-dev.1, has only one setting.

The patch adds `ClientConfig::ech_outer_alpn_protocols` (default `None`),
replaces the outer ALPN **after** encoding the inner hello and **before** HPKE
sealing, and keeps inner ALPN uncompressed so it cannot reference the cover ALPN.
Real ECH, including HRR, uses this setting; non-ECH/GREASE clients are unchanged.
Certificate verification and authenticated ECH retry rules remain intact.

`scripts/vendor-rustls.sh` fetches sources through cargo, so configured registry
mirrors apply:

- `check` verifies `rustls/` is exactly the published source plus the patch; the
  release workflow runs it before testing.
- `outdated` fails when a newer rustls 0.23.x is published. cargo-audit cannot
  see path dependencies, so a weekly workflow runs it instead.
- `update [VERSION]` regenerates `rustls/` (default: newest 0.23.x).

To update, run `update`, then `cargo update -p rustls`, review upstream
advisories, and run the ClientHello privacy regression and live ECH checks:

```sh
scripts/vendor-rustls.sh update
cargo update -p rustls
cargo test
OIXC_LIVE_CONFIG=/path/to/oixc-proxy.conf cargo test --lib live_cover_alpn -- --ignored
```

If the patch no longer applies, edit it against the new release, keeping it
limited to functional changes, or replace it with an upstream equivalent.
