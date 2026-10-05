# rustls ECH cover ALPN patch

`rustls/` is the source of crates.io rustls 0.23.43 (licenses retained).
The application needs separate ALPN values in the encrypted inner ClientHello
and the public outer ClientHello. Upstream 0.23.43 has only one setting.

Local changes add `ClientConfig::ech_outer_alpn_protocols` (default `None`),
replace the outer ALPN **after** encoding the inner hello and **before** HPKE
sealing, and keep inner ALPN uncompressed so it cannot reference the cover ALPN.
Real ECH, including HRR, uses this setting; non-ECH/GREASE clients are unchanged.
Certificate verification and authenticated ECH retry rules remain intact.

When updating rustls, reapply these changes or replace them with an upstream
equivalent and run the ClientHello privacy regression and live ECH checks.
