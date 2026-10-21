# Reality client: a Chrome 133 ClientHello and the hybrid key share

Plan PR 3.3 (`docs/plans/2026-10-15-quality-and-correctness.md`); audit RE-R2,
RE-R4/R7. Written 2026-10-19.

## Compatibility target

The user's servers run **recent sing-box**. Its Reality inbound is
`metacubex/utls` v1.8.7 `RealityConfig` (`sing-box/common/tls/reality_server.go`),
not `sagernet/reality`, which has not changed since 2023. What that server does
with a ClientHello (`metacubex/utls@v1.8.7/reality.go`):

- It derives the auth key from the client's **X25519** share when one is
  present (`len == 32`), and otherwise from the last 32 bytes of an
  **X25519MLKEM768** share (`len == 1184 + 32`) (lines 389-400).
- It relays the ClientHello to the decoy and copies the decoy's choice of
  group. It refuses to proceed (and so forwards the connection to the decoy)
  unless the decoy answered with X25519 (32-byte share) or X25519MLKEM768
  (`1088 + 32`-byte share) (lines 519-523).

**Correction (2026-10-22).** sing-box's REALITY *client* does not send the
uTLS Chrome hello unchanged. It removes X25519MLKEM768 from
supported_groups and key_share before the handshake
(`common/tls/reality_client.go:148-159` in v1.14.3), so the #95 capture
carries X25519 alone. Xray's client sends the hybrid share. shoes offers
it, and `the_hello_has_the_shape_of_sing_boxs_reality_hello` asserts that as
the one difference from sing-box. Whether to offer it is the
`post_quantum` option of PR S.4 (`docs/plans/2026-10-21-lessons-from-steer.md`).

So shoes's X25519-only client works against these servers today. RE-R2's
failure ("forwarded to the decoy") is Xray's REALITY, which requires the
X25519MLKEM768 share. This spec is about looking like Chrome, and it also
makes the client work against Xray.

## What a Chrome 133 ClientHello is

uTLS `HelloChrome_133`, which is `HelloChrome_Auto` and so what sing-box and
Xray clients send by default (`metacubex/utls@v1.8.7/u_parrots.go:884-955`):

- legacy_version 0x0303, a 32-byte random, a 32-byte session id (Reality puts
  its sealed metadata here, unchanged).
- Cipher suites, in order: GREASE, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
  0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
  0x0035. A configured `cipher_suites` list replaces the three TLS 1.3 suites
  only; the rest of the list stays, since a short list is itself a signature.
- Compression: null only.
- Extensions: a GREASE extension (empty) first, a GREASE extension (one zero
  byte) last, and between them, **shuffled** per connection
  (`ShuffleChromeTLSExtensions`):
  server_name (0), extended_master_secret (23), renegotiation_info (65281,
  `00`), supported_groups (10: GREASE, 0x11ec, 0x001d, 0x0017, 0x0018),
  ec_point_formats (11: uncompressed), session_ticket (35, empty),
  ALPN (16: h2, http/1.1), status_request (5: OCSP, empty lists),
  signature_algorithms (13: the eight schemes the client sends today),
  signed_certificate_timestamp (18, empty), key_share (51: GREASE with one
  zero byte, X25519MLKEM768 with 1184 + 32 bytes, X25519 with 32 bytes),
  psk_key_exchange_modes (45: psk_dhe_ke), supported_versions (43: GREASE,
  TLS 1.3, TLS 1.2), compress_certificate (27: brotli),
  application_settings (17613, the new ALPS codepoint: h2), and
  encrypted_client_hello (65037) as GREASE.
- No padding extension.
- The record carrying the ClientHello is labelled TLS 1.0 (`16 03 01`), as
  Chrome, crypto/tls and uTLS label the first record.

GREASE values are RFC 8701's `0x?a?a`. Following BoringSSL, each position
(cipher, group, the two extensions, version, key share) draws its own value
from per-connection randomness, and the two GREASE extensions differ.

GREASE ECH follows BoringSSL's `BoringGREASEECH()`: outer type (0), the HPKE
suite HKDF-SHA256 / AES-128-GCM, a random config id, a random 32-byte `enc`,
and a random payload of 128, 160, 192 or 224 bytes plus the 16-byte tag.

## The hybrid key exchange

X25519MLKEM768 (codepoint 0x11ec, draft-ietf-tls-ecdhe-mlkem):

- The client share is the ML-KEM-768 encapsulation key (1184 bytes) followed
  by an X25519 public key (32).
- The server share is the ML-KEM-768 ciphertext (1088) followed by the
  server's X25519 public key (32).
- The shared secret is the ML-KEM shared secret (32) followed by the X25519
  shared secret (32): 64 bytes into the TLS 1.3 key schedule where X25519
  gives 32.

The X25519 key in the hybrid share and the standalone X25519 share are **the
same key**, as in Go's crypto/tls. The Reality auth key is the X25519 of that
private key with the server's Reality public key, unchanged from today, so
either branch of the server's selection finds the same auth key.

ML-KEM-768 comes from aws-lc-rs 1.18's stable `kem` module
(`DecapsulationKey::generate(&ML_KEM_768)`, `decapsulate`). No new dependency
is needed.

## What the client does with each answer

| ServerHello key_share | Action |
|---|---|
| X25519, 32 bytes | X25519 secret, as today |
| X25519MLKEM768, 1120 bytes | decapsulate, then X25519 on the tail; secret = mlkem ‖ x25519 |
| Any other group or length | fail: "server chose an unsupported key exchange" |
| HelloRetryRequest | fail, with a message that names it (the decoy wanted a group this client does not offer) |

Advertised but not implemented: session tickets, OCSP stapling, SCT,
certificate compression and ALPS. After authentication the client is talking
to the Reality server's own handshake, which is crypto/tls-based and
negotiates none of them. If an EncryptedExtensions carries application_settings,
or a CompressedCertificate (handshake type 25) arrives, the client fails with
a message naming it rather than misparsing. The interop test checks that
neither happens against sing-box.

## Not in this spec's first PR

- RE-R4/R7: an HMAC mismatch falls back to x509 verification and the spider
  behaviour instead of failing, alerts are sent on failure, and the
  ServerHello is sanity-checked. These are part 2. The version in the
  session id is no longer hardcoded: that fix went ahead of part 2 on its
  own (`client_version`, defaulting to Xray-core's latest stable release),
  because Xray v26.7.28 refuses the fixed 1.8.0 by default and the Amnezia
  app installs that Xray.
- ST-S1: a ShadowTLS v3 client built on the same ClientHello and key-schedule
  code. Part 3.
- The shoes Reality **server** accepting an X25519MLKEM768-only client
  (RE-R2's server half). It already authenticates Chrome-shaped clients
  through their X25519 share; servers are off the current focus.

## Tests

- **Shape:** a parsed ClientHello has exactly the Chrome 133 suites, groups,
  key shares and extension set; GREASE first and last; every GREASE value is
  `0x?a?a`; the middle order changes across connections; the key_share
  lengths are 1, 1216 and 32; the 32-byte X25519 matches the hybrid's tail.
- **Hybrid:** against an aws-lc-rs encapsulation of the client's share, the
  derived secret is `ss_mlkem ‖ ss_x25519`; a truncated server share fails.
- **Round trip:** the in-memory pair (`post_handshake_tests::handshaken_pair`)
  still completes against the shoes server.
- **Interop (local, Docker):** a sing-box Reality inbound whose decoy is a
  sing-box TLS inbound on the same host (Go 1.25 crypto/tls, which selects
  X25519MLKEM768 when offered). shoes connects and carries data. The test
  records which group the decoy selected, so it proves the hybrid path ran,
  and repeats with the decoy restricted to X25519. It is not in CI, which has
  no sing-box; the PR records the run.

## Interop result (2026-10-19)

sing-box 1.14.3 (Go 1.26.8, `with_utls`) in Docker, its Reality inbound's
handshake pointing at a sing-box TLS inbound on the same host. A shoes SOCKS
listener chained VLESS over Reality to it; `curl` fetched a small file and
8 MiB of random data (MD5 compared) through each variant:

| Variant | Group the decoy chose | Result |
|---|---|---|
| Default decoy | X25519MLKEM768 (0x11ec) | ok, 8 MiB intact |
| Decoy with `curve_preferences: ["X25519"]` | X25519 (0x001d) | ok, 8 MiB intact |
| Reality + Vision (`xtls-rprx-vision`) | X25519MLKEM768 | ok, 8 MiB intact |

The first run found the one thing the unit tests did not reach: the TLS 1.3
key schedule refused a 64-byte (EC)DHE secret. It now takes 32 or 64 bytes.

## PR split

1. Chrome 133 ClientHello plus the hybrid key exchange, together. Offering
   0x11ec without being able to complete it would break every connection
   whose decoy picks it.
2. RE-R4/R7: x509 fallback and spider, alerts, ServerHello sanity checks.
3. ST-S1 on the same primitives.
