# Protocol and reverse-engineering findings

This document is the compatibility reference for `oixc-proxy`. It preserves
the technical findings previously used by removed `dump-*`, `probe-*`,
`inspect-binary`, bundle and legacy service commands. The primary reference
was `oixcloud-external-proxy-program` v0.0.26; the transport lifecycle was
rechecked against v0.0.27.

## Managed control plane

The built-in API base is `https://oix-api.dler.io`.

| Request | Method and path |
| --- | --- |
| Managed catalog | `GET /api/v1/managed/anywhere/direct` |
| Account information | `POST /api/v1/information` |

All requests use `Authorization: Bearer TOKEN`, `Accept: application/json` and
`User-Agent: oixc-proxy/0.1`. Redirects are not followed and no environment
HTTP proxy is used.

For each managed request:

1. Generate an ephemeral age X25519 identity.
2. Convert its recipient to the standard `age1...` text.
3. Set `X-Anywhere-Timestamp` to decimal Unix seconds.
4. Set `X-Anywhere-Age-Pubkey` to the recipient.
5. Set `X-Anywhere-Signature` to lowercase hex
   `HMAC-SHA256(appSecret, timestamp + "." + recipient)`.

The built-in app secret is:

```text
4a7f27227e2779e5d3e9cd968ba06ceb
```

Known request-signature vector:

```text
timestamp = 1700000000
recipient = age1testrecipient
signature = 5a1e17eb5015033d105e3d36a2f46cbdb6e7795a16f358e967f370c145498a11
```

The managed JSON envelope has `ret`, `msg`, `config` and `userinfo`. `ret` must
be 200 and `config` must be non-empty. Before any decoding, verify
`X-Anywhere-Response-Signature` as lowercase hex:

```text
HMAC-SHA256(appSecret, timestamp + "." + exact_config_string_bytes)
```

Then strictly decode standard Base64, decode age ASCII armor, decrypt with the
ephemeral identity and limit every stage to 8 MiB. Errors must not echo the
token, encrypted payload or decrypted secrets.

## Managed YAML and catalog selection

The decrypted document contains one `proxies` sequence. Unknown YAML fields,
multiple documents, duplicate names and documents above 8 MiB are rejected.

Each supported proxy has:

```yaml
name: string
type: snell
server: string
port: 1..65535
psk: string
version: 4
udp: bool
tfo: bool
reuse: bool
identity: true
obfs-opts:
  mode: ech-tls
  sni: string
  path: string
  alpn: snell-ech/1
  ech-config: standard-base64
  identity-version: 2
  legacy-fallback: false
  skip-cert-verify: false
  preconnect: integer
```

Only proxy names containing `fusion`, using case-insensitive matching, belong
to the premium/love catalog. Filtering is fail-closed: zero matches is an
error, never a fallback to ordinary nodes. A reference capture contained 74
Fusion entries.

## Provider routing

The SOCKS username is:

```text
"name-" + base64url-no-padding(UTF-8 exact managed name)
```

The value must contain only ASCII letters, digits, `-` and `_`, and fit the
SOCKS5 255-byte username limit.

The password is:

```text
base64url-no-padding(
  HMAC-SHA256(accessToken, "oixc-proxy/provider-routing/v1")
)
```

Authentication compares both values in constant time and returns the same
failure for a wrong password or unknown selector. The provider never contains
the token, remote address, PSK or ECH bytes.

Each Surge line is:

```text
NAME = socks5, OUTBOUND_IP, PORT, SELECTOR, ROUTING_SECRET, test-timeout=45
```

UDP-capable entries append:

```text
, udp-relay=true, test-udp=example.com@1.1.1.1
```

## Signed private DNS

Managed names under `cloud-nodes.com` use the private resolver
`124.221.68.73:1053`. Other names use the system resolver.

The Ed25519 seed is standard Base64:

```text
QiXXv81GasAAq3TfApAmFZ7kOjj+QC/I21N5MP39YNY=
```

Normalize the host to lowercase, trim whitespace and one trailing dot. Let:

```text
window  = unix_seconds / 300
message = normalized_host + "|" + decimal(window)
sig     = Ed25519(seed, message)
query   = lower(base32-no-pad(sig[0:32]))
        + "."
        + lower(base32-no-pad(sig[32:64]))
        + "."
        + normalized_host
```

Cache valid A/AAAA results by normalized host for five minutes. DNS names are
limited to 253 bytes and each label to 63 bytes.

Known vector for `Node.Cloud-Nodes.Com.` at Unix `1800000000`:

```text
rf6fz4on43us6trf7jp6mfq4s65u3ezhcfdwkjkefhxdahthgmpq.h
hpdgqn2h4e7yks6tkn7zdhfb4u2io4btsa4on6ngicvhz5bpqgq.no
de.cloud-nodes.com
```

The line wrapping above is editorial; concatenate it without newlines.

## ECH-TLS transport

Decode `ech-config` using strict standard Base64. The result must be 4 through
65536 bytes. Its first two bytes are a big-endian length equal to the remaining
byte count.

The TLS client must:

- use TLS 1.3 only;
- enable real ECH, never GREASE or plaintext fallback;
- verify the system certificate chain and configured SNI;
- offer only ALPN `snell-ech/1`;
- reject an ECH rejection or unexpected ALPN; and
- export 32 bytes with label
  `EXPORTER-Dler-Snell-Identity-v2` and no context.

The exporter binds the clear Identity v2 preface to this exact TLS session.
Unsupported profiles are rejected before node network access.

## Snell Identity v2

Constants:

```text
magic      = "DLSNID02"
root-label = "oix/snell-ech/2/auth-root"
```

Derivation:

```text
rootLabelHash = SHA256(root-label)
root          = HMAC-SHA256(rootLabelHash, PSK bytes)
identityKey   = HMAC-SHA256(root, "identity"       || 0x01)
authKey       = HMAC-SHA256(root, "authentication" || 0x01)
identity      = identityKey[0:16]
auth          = HMAC-SHA256(
                  authKey,
                  magic || exporter32 || nonce16 || identity
                )[0:16]
wire          = nonce16 || magic || identity || auth
```

The wire preface is 56 bytes. The 16-byte nonce is also the client record salt.

Known vector using PSK `test-psk-2026`, exporter bytes `00..1f` and nonce bytes
`a0..af`:

```text
a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
444c534e49443032
0494ed911b162dc772388b2de2a92fdd
53c9a6fc01e213a447210cefa2537d51
```

## Snell v4 records

Derive 32 bytes with Argon2id:

```text
password = PSK bytes
salt     = 16-byte connection salt
time     = 3
memory   = 8 KiB
lanes    = 1
version  = 0x13
```

Use the first 16 bytes as the AES-128-GCM key. Known key vector for
`test-psk-2026` and salt `a0..af`:

```text
f500729fecd347f4378828c643423963
```

The 12-byte AES-GCM nonce begins at zero and increments little-endian after
every encrypted header and every non-empty encrypted payload.

The seven-byte plaintext header is:

```text
04 00 00 padding_len_be16 payload_len_be16
```

The encrypted header is 23 bytes. Payload and padding lengths are independently
limited to 16383. A non-empty payload is encrypted separately and gains a
16-byte tag. Padding bytes are random.

For indexes `0, 2, 4, ...` below `min(paddingLen, payloadCiphertextLen)`, swap
the corresponding padding and payload-ciphertext bytes. Reverse the same swaps
before decryption.

A record with zero payload and zero padding is the session zero record. Zero
payload with nonzero padding is invalid.

The client identity already carries the initial record salt, so the first
client record omits the normal salt prefix. Server-to-client records begin with
their own 16-byte salt.

## Requests, UDP and first flight

TCP CONNECT:

```text
01 command 00 host_len host_bytes port_be16
```

`command=1` opens a non-reusable session; `command=5` starts a reusable session.
Hosts are preserved exactly and are limited to 255 bytes. UDP ASSOCIATE is:

```text
01 06 00
```

The initial record uses random padding from 1 through:

```text
0x491 - connect_request_length
```

Identity v2 and that encrypted record must be concatenated and sent with one
TLS write. Splitting them adds a network round trip on affected nodes.

The SOCKS success reply is sent after the initial flight, before waiting for
the Snell CONNECT status. This allows the application to send its first TLS
ClientHello immediately. The first upstream read consumes:

- `00` for success;
- `02 code message_length message` for a rejection; or
- any other byte as an unexpected status.

Application writes are allowed while the status is pending.

One UDP forward frame begins with command `01`, followed by:

- domain: one-byte nonzero length and exact host bytes;
- IPv4: `00 04` and four address bytes; or
- IPv6: `00 06` and sixteen address bytes;

then the big-endian port and datagram payload. Server responses start with
address type `04` or `06`, raw address, port and payload.

## Reuse lifecycle

At application upload EOF, send a zero record. The transport is reusable only
after the server also returns a zero record and no buffered bytes remain.
Waiting for the server zero is limited to two seconds; timeout, malformed
records, extra unread data or a missing zero retires the physical connection.

Idle pools are per node. Defaults are 8 idle connections, 32 uses per physical
connection and 90 seconds idle time. Only a complete, unchanged managed profile
may retain its pool across a catalog refresh.

## Subscription catalog layer

The direct managed payload supplies transport parameters, but is not the full
generic user-visible catalog contract. The reference client also uses:

```text
POST /api/v1/information
  -> stable plan identity / flow_level
POST /api/v1/managed/surge
  -> JSON smart URL
  -> plan mode plus optional query parameters
  -> parsed Surge subscription: visible names, membership and order

GET /api/v1/managed/anywhere/direct
  -> Snell/ECH connection parameters
```

Known identifiers include `love`, `premium`, `fusion`, `fusion_advanced` and
`fusion_premium`. Known mode strings include `premium`, `overseas` and
`emergency`; historical parameters include values such as `area=hk`.

The subscription entries are matched with direct transport entries before
local policies are generated. Reference v0.0.26 has distinct errors for an
empty `smart` URL and an unresolvable subscription, so catalog failure must
not fall back to the unfiltered direct payload. The captured premium/love list
contained 74 entries in panel order, including two `[Advanced]` and two
`[Premium]` names.

The current service intentionally implements the narrower, verified
Fusion-name rule. Full support for other plans requires recovering the
catalog-to-transport matching contract first.

## Removed binary constant decoding

The former binary-inspection command looked for raw
`v2:[A-Za-z0-9+/]+={0,2}` strings.

To decode one:

1. Remove `v2:` and strictly decode standard Base64.
2. Treat the first eight decoded bytes as `seed`; the remainder is the
   ciphertext.
3. Concatenate this 32-byte material:

   ```text
   2f 84 b1 6d c0 39 9e 47 f2 1b a8 53 ce 70 35 d9
   61 cd 0a 97 4e e3 28 bf 14 8c 52 f9 3d a6 1f c7
   ```

4. Derive:

   ```text
   fixed_key = SHA256(material || "oix-obf-v2-exp")
   ```

5. Generate stream blocks beginning at counter zero:

   ```text
   block = SHA256(fixed_key || seed || uint32_be(counter))
   ```

6. XOR the ciphertext with consecutive stream blocks.

Known decoded constants include:

```text
oix-api.dler.io
/api/v1/information
/api/v1/managed/anywhere/direct
Authorization
"Bearer " (including the trailing ASCII space)
X-Anywhere-Timestamp
X-Anywhere-Signature
X-Anywhere-Age-Pubkey
X-Anywhere-Response-Signature
```

The active runtime does not need the decoder; all required constants are
documented in source. This procedure is retained so future diagnostic tooling
does not need to repeat binary analysis.

## Remaining unknowns

- The exact key and normalization rules used to match subscription catalog
  entries to direct transport entries remain unknown.
- Plan-mode precedence, explicit query precedence, alias handling, duplicate
  names and missing matches are not recovered.
- Non-Fusion plans require the full
  `information -> managed/surge -> smart` flow; publishing all direct nodes
  would be incorrect.
- DNS-based application-configuration refresh behavior outside managed-node
  address resolution is not implemented.
